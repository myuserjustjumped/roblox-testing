#!/usr/bin/env python3
from __future__ import annotations

import argparse
import itertools
import logging
import os
import queue
import signal
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import requests

DEFAULT_COOKIE_FILE = "cookies.txt"
DEFAULT_USERS_FILE = "users.txt"
DEFAULT_REPORTED_FILE = "reported.txt"
DEFAULT_ATTEMPTED_FILE = "attempted.txt"


def env_path(name: str, default: str) -> str:
    val = os.environ.get(name, "").strip()
    return val or default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


DEFAULT_MAX_RUNTIME_SECONDS = int(os.environ.get("REPORT_MAX_RUNTIME_SECONDS", "17400"))
REPORTS_PER_MINUTE = int(os.environ.get("REPORTS_PER_MINUTE", "6"))
REPORT_WORKERS_MAX = int(os.environ.get("REPORT_WORKERS_MAX", "20"))
MAX_TARGET_RETRIES = int(os.environ.get("MAX_TARGET_RETRIES", "5"))
MAX_RATE_LIMIT_RETRIES = int(os.environ.get("MAX_RATE_LIMIT_RETRIES", "200"))
RETRY_NETWORK_ERRORS = _env_bool("RETRY_NETWORK_ERRORS", False)
SKIP_ATTEMPTED = _env_bool("SKIP_ATTEMPTED", True)
STRICT_CONFIG = _env_bool("REPORT_STRICT_CONFIG", False)

REPORT_WINDOW = 60
RATE_LIMIT_SLEEP = 60
WORKER_POLL_INTERVAL = 1.0
NETWORK_BACKOFF_BASE = 0.25
NETWORK_BACKOFF_MAX = 2.0
SHUTDOWN_GRACE = 90
REQUEST_TIMEOUT = 30
REQUEST_TIMEOUT_CONNECT = 10
VALIDATION_TIMEOUT = 15
LEASE_POLL = 1.0
EPOCH_THRESHOLD = 1_000_000_000
STARTUP_JITTER = float(os.environ.get("REPORT_STARTUP_JITTER", "0"))

AUTH_URL = os.environ.get("AUTH_URL", "https://users.roblox.com/v1/users/authenticated")
REPORT_URL = os.environ.get("REPORT_URL", "https://apis.roblox.com/abuse-reporting/v1/abuse-report")
VECTOR = "user_profile"
ENTRY_POINT = "web"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) "
    "Gecko/20100101 Firefox/159.0"
)

CATEGORIES = [
    ("Bullying", "ABUSE_CATEGORY_BULLYING"),
    ("Cheating", "ABUSE_CATEGORY_CHEATING"),
    ("Discrimination", "ABUSE_CATEGORY_HATE_SPEECH"),
    ("Extreme violence", "ABUSE_CATEGORY_VIOLENCE_OR_TERRORISM"),
    ("Romance or sex", "ABUSE_CATEGORY_DATING_OR_SEXUAL_CONTENT"),
    ("Outside links and trading", "ABUSE_CATEGORY_OFFSITE_LINKS"),
    ("Sharing personal information", "ABUSE_CATEGORY_PERSONAL_QUESTION"),
    ("Scams", "ABUSE_CATEGORY_SCAMMING"),
    ("Swearing", "ABUSE_CATEGORY_SWEARING"),
    ("Spam", "ABUSE_CATEGORY_SPAMMING"),
    ("Dangerous suggestions", "ABUSE_CATEGORY_DANGEROUS_ASK"),
    ("Real-life events", "ABUSE_CATEGORY_REAL_LIFE_EVENTS"),
    ("Asking you to do things that aren't safe", "ABUSE_CATEGORY_SUICIDE_OR_SELF_HARM"),
]

SURFACES = [
    ("Username, display name, \"About\" section", "username"),
    ("Avatar, clothes, accessories", "avatar"),
    ("Text chat messages", "textChat"),
    ("Voice chat messages", "voiceChat"),
    ("Behavior in a game or experience", "inGameBehavior"),
]

log = logging.getLogger("reporter")
_session_local = threading.local()
_rotation_listener = None


def set_rotation_listener(listener) -> None:
    global _rotation_listener
    _rotation_listener = listener


def get_session() -> requests.Session:
    s = getattr(_session_local, "session", None)
    if s is None:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=50, max_retries=0)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        _session_local.session = s
    return s


def base_headers(cookie_header: str) -> dict:
    return {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json;charset=utf-8",
        "Cookie": cookie_header,
        "Origin": "https://www.roblox.com",
        "Referer": "https://www.roblox.com/",
        "User-Agent": UA,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._all: list[Counter] = []
        self._tls = threading.local()

    def _local(self) -> Counter:
        c = getattr(self._tls, "counter", None)
        if c is None:
            c = Counter()
            self._tls.counter = c
            with self._lock:
                self._all.append(c)
        return c

    def bump(self, key: str, n: int = 1) -> None:
        self._local()[key] += n

    def merged(self) -> Counter:
        with self._lock:
            total = Counter()
            for c in self._all:
                total.update(c)
            return total


def parse_cookie_line(line: str) -> dict | None:
    stripped = line.strip()
    if not stripped:
        return None
    body = stripped[len("#HttpOnly_"):] if stripped.startswith("#HttpOnly_") else stripped
    parts = body.split("\t")
    if len(parts) >= 7 and parts[-2].strip().lstrip(".").lower() == "roblosecurity":
        value = parts[-1].strip()
        if value:
            return {"header": ".ROBLOSECURITY=" + value, "value": value}
        return None
    if stripped.startswith("#"):
        return None
    if ".ROBLOSECURITY=" in stripped:
        value = stripped.split(".ROBLOSECURITY=", 1)[1].split(";")[0].strip()
        return {"header": stripped, "value": value} if value else None
    value = "".join(stripped.split())
    return {"header": ".ROBLOSECURITY=" + value, "value": value} if value else None


def first_int(raw: str | None) -> int | None:
    if not raw:
        return None
    for part in raw.split(","):
        token = part.strip().split(";")[0].strip()
        if token.isascii() and token.isdigit():
            return int(token)
    return None


def header_value(r: requests.Response, *names: str) -> str | None:
    for name in names:
        val = r.headers.get(name)
        if val is not None:
            return val
    return None


def rate_limit_reset(r: requests.Response) -> float | None:
    raw = header_value(r, "x-ratelimit-reset", "x-rate-limit-reset")
    val = first_int(raw)
    if val is None:
        return None
    now = time.time()
    if val >= EPOCH_THRESHOLD:
        return val if val > now else now + 1.0
    if val > 0:
        return now + val
    return now + RATE_LIMIT_SLEEP


class Cookie:
    _ids = itertools.count(1)

    def __init__(self, header: str, value: str) -> None:
        self.id = next(self._ids)
        self.header = header
        self.value = value
        self.csrf_token: str | None = None
        self.remaining = REPORTS_PER_MINUTE
        self.reset_at = time.time() + REPORT_WINDOW
        self.invalid = False
        self._lock = threading.Lock()
        self.ok_count = 0
        self.fail_count = 0

    def cookie_header(self) -> str:
        with self._lock:
            return self.header

    def set_value(self, new_value: str) -> None:
        with self._lock:
            if new_value == self.value:
                return
            old_value = self.value
            self.value = new_value
            parts = [p.strip() for p in self.header.split(";") if p.strip()]
            out, replaced = [], False
            for part in parts:
                if part.startswith(".ROBLOSECURITY="):
                    out.append(".ROBLOSECURITY=" + new_value)
                    replaced = True
                else:
                    out.append(part)
            if not replaced:
                out.append(".ROBLOSECURITY=" + new_value)
            self.header = "; ".join(out)
        listener = _rotation_listener
        if listener is not None:
            try:
                listener(old_value, new_value)
            except Exception as exc:
                log.warning(
                    "cookie #%d rotation persistence failed (%s)",
                    self.id, type(exc).__name__,
                )

    def is_invalid(self) -> bool:
        with self._lock:
            return self.invalid

    def set_invalid(self) -> None:
        with self._lock:
            self.invalid = True

    def next_reset(self) -> float:
        with self._lock:
            return self.reset_at

    def try_consume(self, now: float) -> bool:
        with self._lock:
            if self.invalid:
                return False
            if now >= self.reset_at:
                self.remaining = REPORTS_PER_MINUTE
                self.reset_at = now + REPORT_WINDOW
            if self.remaining > 0:
                self.remaining -= 1
                return True
            return False

    def refund(self) -> None:
        with self._lock:
            if self.remaining < REPORTS_PER_MINUTE:
                self.remaining += 1

    def apply_rate_limit(self, reset_epoch: float | None = None) -> None:
        now = time.time()
        with self._lock:
            already_cooling = self.remaining <= 0 and self.reset_at > now
            self.remaining = 0
            target = reset_epoch if reset_epoch and reset_epoch > now else now + RATE_LIMIT_SLEEP
            self.reset_at = max(self.reset_at, target) if already_cooling else target

    def update_from_response(self, r: requests.Response) -> None:
        remaining = first_int(header_value(r, "x-ratelimit-remaining", "x-rate-limit-remaining"))
        reset_at = rate_limit_reset(r)
        now = time.time()
        with self._lock:
            if remaining is not None:
                self.remaining = min(self.remaining, max(0, remaining))
            if reset_at is not None and reset_at > now:
                self.reset_at = max(self.reset_at, reset_at)
        new_value = r.cookies.get(".ROBLOSECURITY")
        if new_value:
            self.set_value(new_value.strip())


class PoolExhausted(Exception):
    pass


class CookiePool:
    def __init__(self, cookies: list[Cookie]) -> None:
        self.cookies = cookies
        self._cond = threading.Condition()
        self._rr = 0
        self._valid = [c for c in cookies if not c.is_invalid()]

    def lease(self, stop_event: threading.Event) -> Cookie | None:
        with self._cond:
            while True:
                if stop_event.is_set():
                    return None
                self._valid = [c for c in self._valid if not c.is_invalid()]
                if not self._valid:
                    raise PoolExhausted
                now = time.time()
                n = len(self._valid)
                for _ in range(n):
                    c = self._valid[self._rr % n]
                    self._rr += 1
                    if c.try_consume(now):
                        return c
                soonest = min(c.next_reset() for c in self._valid)
                delay = max(0.2, min(LEASE_POLL, soonest - now))
                if self._cond.wait(timeout=delay):
                    pass

    def refill(self) -> None:
        with self._cond:
            self._cond.notify_all()


def load_cookies(path: str) -> list[Cookie]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        sys.exit(f"[-] {path} not found")
    parsed = []
    for lineno, line in enumerate(lines, 1):
        try:
            p = parse_cookie_line(line)
        except Exception as exc:
            log.warning("%s:%d unparseable cookie line (%s)", path, lineno, exc)
            continue
        if p and p["value"]:
            parsed.append(p)
        elif line.strip() and not line.lstrip().startswith("#"):
            log.warning("%s:%d line is not a recognized cookie format", path, lineno)
    if not parsed:
        sys.exit(f"[-] No usable .ROBLOSECURITY values in {path}")
    return [Cookie(p["header"], p["value"]) for p in parsed]


def validate_cookie(cookie: Cookie) -> bool:
    try:
        r = get_session().get(AUTH_URL, headers=base_headers(cookie.cookie_header()),
                              timeout=VALIDATION_TIMEOUT)
    except requests.RequestException:
        return False
    cookie.update_from_response(r)
    if r.status_code == 429:
        return True
    if r.status_code != 200:
        return False
    try:
        info = r.json()
    except ValueError:
        return False
    return isinstance(info, dict)


def validate_all_cookies(cookies: list[Cookie]) -> list[Cookie]:
    if not cookies:
        return []
    workers = max(1, min(len(cookies), 10))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(validate_cookie, cookies))
    valid: list[Cookie] = []
    for c, ok in zip(cookies, results):
        if ok:
            valid.append(c)
            log.info("cookie #%d validated", c.id)
        else:
            log.warning("cookie #%d invalid, skipped", c.id)
    return valid


def load_user_ids(path: str) -> list[int]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        sys.exit(f"[-] {path} not found")
    ids: list[int] = []
    seen: set[int] = set()
    for lineno, line in enumerate(raw_lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.isascii() or not stripped.isdigit():
            log.warning("%s:%d skipping non-numeric id", path, lineno)
            continue
        uid = int(stripped)
        if uid > 0 and uid not in seen:
            seen.add(uid)
            ids.append(uid)
    return ids


def load_id_set(path: str) -> set[int]:
    ids: set[int] = set()
    if not os.path.exists(path):
        return ids
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if stripped.isascii() and stripped.isdigit():
                ids.add(int(stripped))
    return ids


class IdLog:
    def __init__(self, path: str, compact: bool = True) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.ids: set[int] = load_id_set(path)
        self._wrote = 0
        if compact:
            self.compact()

    def compact(self, drop: set[int] | None = None) -> None:
        with self._lock:
            if drop:
                self.ids -= drop
            if not self.ids and not os.path.exists(self.path):
                return
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for uid in sorted(self.ids):
                    f.write(f"{uid}\n")
            os.replace(tmp, self.path)

    def add(self, uid: int) -> None:
        with self._lock:
            self.ids.add(uid)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(f"{uid}\n")
                f.flush()
                os.fsync(f.fileno())
            self._wrote += 1

    def __contains__(self, uid: int) -> bool:
        with self._lock:
            return uid in self.ids


def _normalize_config(env_name: str, raw: str, table, default: str) -> tuple[str, str]:
    raw = raw.strip()
    if not raw:
        return default, "default"
    needle = raw.lower()
    for label, api in table:
        if needle in {api.lower(), label.lower()}:
            return api, env_name
    known = ", ".join(api for _l, api in table)
    msg = f"{env_name}={raw!r} is not a known value; known values: {known}"
    if STRICT_CONFIG:
        sys.exit(f"[-] {msg}")
    log.error("%s -- falling back to default %r (set REPORT_STRICT_CONFIG=1 to make this fatal)",
              msg, default)
    return default, f"invalid {env_name}, fell back to default"


def resolve_config() -> tuple[str, str, str]:
    category, cat_src = _normalize_config(
        "REPORT_CATEGORY", os.environ.get("REPORT_CATEGORY", ""), CATEGORIES, CATEGORIES[0][1])
    surface, surf_src = _normalize_config(
        "REPORT_SURFACE", os.environ.get("REPORT_SURFACE", ""), SURFACES, SURFACES[0][1])
    comment = os.environ.get("REPORT_COMMENT", "")[:1000]
    log.info("category=%s (from %s)  surface=%s (from %s)  comment=%s",
             category, cat_src, surface, surf_src, "set" if comment else "empty")
    return category, surface, comment


def submit_report(cookie: Cookie, target_id: int, category: str, surface: str, comment: str):
    headers = base_headers(cookie.cookie_header())
    if cookie.csrf_token:
        headers["x-csrf-token"] = cookie.csrf_token
    payload = {
        "abuseVector": VECTOR,
        "category": category,
        "comment": comment,
        "custom": {"ENTRY_POINT": ENTRY_POINT, "REPORTED_ABUSE_SURFACE": surface},
        "targetIdStr": str(target_id),
        "targetType": "user",
    }
    timeout = (REQUEST_TIMEOUT_CONNECT, REQUEST_TIMEOUT)
    try:
        r = get_session().post(REPORT_URL, json=payload, headers=headers, timeout=timeout)
    except requests.exceptions.ConnectTimeout as e:
        return None, e, False
    except requests.exceptions.ConnectionError as e:
        refused = "refused" in str(e).lower() or "resolve" in str(e).lower()
        return None, e, not refused
    except requests.RequestException as e:
        return None, e, True

    if r.status_code == 403:
        token = r.headers.get("x-csrf-token")
        if token and token != cookie.csrf_token:
            cookie.csrf_token = token
            headers["x-csrf-token"] = token
            try:
                r = get_session().post(REPORT_URL, json=payload, headers=headers, timeout=timeout)
            except requests.RequestException as e:
                return None, e, True
    return r, None, True


def is_success(status: int) -> bool:
    return 200 <= status < 300


def is_permanent_rejection(status: int) -> bool:
    return status in (400, 404, 405, 409, 410, 413, 415, 422)


class RetryBook:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failures: dict[int, int] = {}
        self.throttled: dict[int, int] = {}

    def fail(self, target: int) -> bool:
        with self.lock:
            n = self.failures.get(target, 0) + 1
            if n > MAX_TARGET_RETRIES:
                self.failures.pop(target, None)
                self.throttled.pop(target, None)
                return False
            self.failures[target] = n
            return True

    def throttle(self, target: int) -> bool:
        with self.lock:
            n = self.throttled.get(target, 0) + 1
            if n > MAX_RATE_LIMIT_RETRIES:
                self.throttled.pop(target, None)
                return False
            self.throttled[target] = n
            return True

    def clear(self, target: int) -> None:
        with self.lock:
            self.failures.pop(target, None)
            self.throttled.pop(target, None)

    def backoff(self, target: int) -> float:
        with self.lock:
            n = self.failures.get(target, 0)
        return min(NETWORK_BACKOFF_MAX, NETWORK_BACKOFF_BASE * (n + 1))


class InFlight:
    def __init__(self) -> None:
        self._n = 0
        self._lock = threading.Lock()

    def __enter__(self) -> "InFlight":
        with self._lock:
            self._n += 1
        return self

    def __exit__(self, *exc) -> None:
        with self._lock:
            self._n -= 1

    def count(self) -> int:
        with self._lock:
            return self._n


def handle_target(
    name, target, pool, stop_event, stats, category, surface, comment,
    book, attempted_log, retry_q, reported_log,
) -> None:
    try:
        cookie = pool.lease(stop_event)
    except PoolExhausted:
        log.error("[%s] no valid cookies left; stopping", name)
        stop_event.set()
        return
    if cookie is None:
        return

    if attempted_log is not None:
        attempted_log.add(target)

    r, err, may_have_sent = submit_report(cookie, target, category, surface, comment)
    if err is not None:
        cookie.refund()
        pool.refill()
        if may_have_sent and not RETRY_NETWORK_ERRORS:
            stats.bump("unknown_send")
            book.clear(target)
            log.warning("[%s] %s network error (%s); request may have been accepted, "
                        "not retrying (at-most-once)", name, target, type(err).__name__)
            return
        stats.bump("network_error")
        if stop_event.wait(timeout=book.backoff(target)):
            return
        if book.fail(target):
            stats.bump("retried")
            retry_q.put(target)
        else:
            stats.bump("dropped")
            log.warning("[%s] dropping %s after repeated network errors", name, target)
        return

    cookie.update_from_response(r)
    pool.refill()

    if is_success(r.status_code):
        cookie.ok_count += 1
        reported_log.add(target)
        book.clear(target)
        stats.bump("reported")
        log.info("[%s] reported %s (cookie=%s, HTTP %s)", name, target, cookie.id, r.status_code)

    elif r.status_code == 429:
        cookie.fail_count += 1
        stats.bump("rate_limited")
        cookie.apply_rate_limit(rate_limit_reset(r))
        pool.refill()
        if book.throttle(target):
            stats.bump("throttled_requeue")
            retry_q.put(target)
        else:
            stats.bump("dropped")
            log.warning("[%s] dropping %s: permanently rate limited", name, target)

    elif r.status_code == 401:
        cookie.fail_count += 1
        cookie.set_invalid()
        pool.refill()
        stats.bump("auth_error")
        log.warning("[%s] 401 with cookie #%d; cookie retired", name, cookie.id)
        if book.fail(target):
            retry_q.put(target)
        else:
            stats.bump("dropped")

    elif r.status_code == 403:
        cookie.fail_count += 1
        stats.bump("http_error")
        log.warning("[%s] 403 on %s (cookie=%s) after CSRF refresh", name, target, cookie.id)
        if book.fail(target):
            retry_q.put(target)
        else:
            stats.bump("dropped")

    elif is_permanent_rejection(r.status_code):
        stats.bump("rejected")
        book.clear(target)
        log.warning("[%s] HTTP %s on %s: permanent rejection, not retrying",
                    name, r.status_code, target)

    else:
        cookie.fail_count += 1
        stats.bump("http_error")
        log.warning("[%s] HTTP %s on %s", name, r.status_code, target)
        if book.fail(target):
            retry_q.put(target)
        else:
            stats.bump("dropped")


def reporter_worker(
    name, report_q, retry_q, pool, stop_event, stats,
    category, surface, comment, book, attempted_log, in_flight, reported_log,
):
    while not stop_event.is_set():
        target = None
        try:
            target = retry_q.get_nowait()
        except queue.Empty:
            pass
        if target is None:
            try:
                target = report_q.get(timeout=WORKER_POLL_INTERVAL)
            except queue.Empty:
                continue

        with in_flight:
            try:
                handle_target(name, target, pool, stop_event, stats, category,
                              surface, comment, book, attempted_log, retry_q,
                              reported_log)
            except Exception:
                log.exception("[%s] unhandled error on %s", name, target)
                if not stop_event.is_set() and book.fail(target):
                    retry_q.put(target)


def deadline_watchdog(deadline: float, stop_event: threading.Event, cap_seconds: int) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            log.warning("runtime cap (%ds) reached; shutting down", cap_seconds)
            stop_event.set()
            return
        if stop_event.wait(timeout=min(5.0, remaining)):
            return


def build_pending(all_ids, reported, attempted, skip_attempted: bool) -> list[int]:
    pending = []
    for uid in all_ids:
        if uid in reported:
            continue
        if skip_attempted and uid in attempted:
            continue
        pending.append(uid)
    return pending


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Submit reports for targets listed in users.txt")
    parser.add_argument("--max-runtime", type=int, default=DEFAULT_MAX_RUNTIME_SECONDS)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--force", action="store_true",
                        help="ignore attempted.txt and re-send journalled targets")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    category, surface, comment = resolve_config()

    cookie_file = env_path("COOKIE_FILE", DEFAULT_COOKIE_FILE)
    users_file = env_path("USERS_FILE", DEFAULT_USERS_FILE)
    reported_file = env_path("REPORTED_FILE", DEFAULT_REPORTED_FILE)
    attempted_file = env_path("ATTEMPTED_FILE", DEFAULT_ATTEMPTED_FILE)

    if os.environ.get("COOKIES_REPO", "").strip() and os.environ.get("COOKIES_PAT", "").strip():
        try:
            from refresh import GitHubCookieStore

            rotation_store = GitHubCookieStore(
                os.environ["COOKIES_REPO"],
                os.environ["COOKIES_PAT"],
                os.environ.get("COOKIES_REF", "main"),
                local_path=cookie_file,
            )
            set_rotation_listener(rotation_store.rotate)
        except Exception as exc:
            log.warning("cookie rotation persistence disabled (%s)", type(exc).__name__)

    cookies = load_cookies(cookie_file)
    log.info("loaded %d cookie line(s)", len(cookies))
    valid = validate_all_cookies(cookies)
    if not valid:
        log.error("no valid cookies remain")
        return 3

    all_ids = load_user_ids(users_file)

    reported_log = IdLog(reported_file)
    attempted_log = None if args.force else IdLog(attempted_file)
    if not SKIP_ATTEMPTED and attempted_log is not None:
        log.warning("SKIP_ATTEMPTED=0: journalled ids will be re-sent (duplicate risk)")
        pending = build_pending(all_ids, reported_log.ids, set(), False)
    else:
        attempted = attempted_log.ids if attempted_log is not None else set()
        pending = build_pending(all_ids, reported_log.ids, attempted, True)
        if attempted_log is not None:
            attempted_log.compact(drop=set(reported_log.ids))

    log.info("users.txt=%d  reported=%d  attempted=%d  pending=%d",
             len(all_ids), len(reported_log.ids),
             len(attempted_log.ids) if attempted_log else 0, len(pending))

    if not pending:
        log.info("no pending targets; exiting")
        return 0

    if STARTUP_JITTER > 0:
        time.sleep(STARTUP_JITTER)

    pool = CookiePool(valid)
    stop_event = threading.Event()

    def _handle_signal(signum, _frame):
        log.warning("received signal %s; shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    start_mono = time.monotonic()
    deadline_mono = start_mono + args.max_runtime

    report_q: queue.Queue = queue.Queue()
    retry_q: queue.Queue = queue.Queue()
    book = RetryBook()
    stats = Stats()
    in_flight = InFlight()

    for uid in pending:
        report_q.put(uid)

    report_workers = max(2, min(REPORT_WORKERS_MAX, len(valid) * 2))
    log.info("starting %d worker(s) with %d cookie(s)", report_workers, len(valid))
    reporters = [
        threading.Thread(
            target=reporter_worker,
            args=(f"w-{i}", report_q, retry_q, pool, stop_event, stats,
                  category, surface, comment, book, attempted_log, in_flight,
                  reported_log),
            daemon=True,
            name=f"w-{i}",
        )
        for i in range(report_workers)
    ]
    for t in reporters:
        t.start()

    watchdog = threading.Thread(
        target=deadline_watchdog,
        args=(deadline_mono, stop_event, args.max_runtime),
        daemon=True, name="watchdog",
    )
    watchdog.start()

    idle_since: float | None = None
    while not stop_event.is_set():
        busy = not report_q.empty() or not retry_q.empty() or in_flight.count() > 0
        if busy:
            idle_since = None
        else:
            if idle_since is None:
                idle_since = time.monotonic()
            elif time.monotonic() - idle_since > 2.0:
                log.info("all queues drained and nothing in flight; shutting down")
                stop_event.set()
                break
        if stop_event.wait(timeout=0.5):
            break

    grace_start = time.monotonic()
    for t in reporters:
        remaining = max(1.0, SHUTDOWN_GRACE - (time.monotonic() - grace_start))
        if remaining <= 1.0:
            break
        t.join(timeout=remaining)

    abandoned = in_flight.count()
    if abandoned:
        log.warning("%d request(s) still in flight at shutdown; they are journalled "
                    "in %s and will not be re-sent", abandoned, attempted_file)

    final = stats.merged()
    elapsed = time.monotonic() - start_mono
    print("\n=== summary ===")
    print(f"runtime                 : {elapsed:.1f}s (cap {args.max_runtime}s)")
    print(f"category                : {category}")
    print(f"surface                 : {surface}")
    print(f"pending at start        : {len(pending)}")
    print(f"reports accepted (2xx)  : {final.get('reported', 0)}")
    print(f"rate-limit hits (429)   : {final.get('rate_limited', 0)}")
    print(f"network errors (retried): {final.get('network_error', 0)}")
    print(f"unknown send (no retry) : {final.get('unknown_send', 0)}")
    print(f"permanent rejections    : {final.get('rejected', 0)}")
    print(f"targets retried         : {final.get('retried', 0)}")
    print(f"targets throttled again : {final.get('throttled_requeue', 0)}")
    print(f"auth/http errors        : {final.get('http_error', 0)} + {final.get('auth_error', 0)} auth")
    print(f"dropped targets         : {final.get('dropped', 0)}")
    print(f"valid cookies at start  : {len(valid)}")
    for c in valid:
        print(f"  cookie #{c.id}: ok={c.ok_count} fail={c.fail_count}"
              f"{' INVALID' if c.is_invalid() else ''}")

    accepted = final.get("reported", 0)
    problems = sum(final.get(k, 0) for k in ("network_error", "http_error", "auth_error", "unknown_send"))
    if accepted == 0 and problems > 0:
        log.error("no reports accepted but %d error(s) occurred; failing so the chain stops",
                  problems)
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
