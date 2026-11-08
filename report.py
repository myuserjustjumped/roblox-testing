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

COOKIE_FILE = os.environ.get("COOKIE_FILE", "cookies.txt")
USERS_FILE = os.environ.get("USERS_FILE", "users.txt")
REPORTED_FILE = os.environ.get("REPORTED_FILE", "reported.txt")

DEFAULT_MAX_RUNTIME_SECONDS = int(os.environ.get("REPORT_MAX_RUNTIME_SECONDS", "19800"))
REPORTS_PER_MINUTE = int(os.environ.get("REPORTS_PER_MINUTE", "6"))
REPORT_WORKERS_MAX = int(os.environ.get("REPORT_WORKERS_MAX", "10"))
MAX_TARGET_RETRIES = int(os.environ.get("MAX_TARGET_RETRIES", "5"))
REPORT_WINDOW = 60
RATE_LIMIT_SLEEP = 60
WORKER_POLL_INTERVAL = 1.0
NETWORK_BACKOFF_BASE = 0.25
NETWORK_BACKOFF_MAX = 2.0
SHUTDOWN_GRACE = 90
REQUEST_TIMEOUT = 30
VALIDATION_TIMEOUT = 15
LEASE_POLL = 1.0
EPOCH_THRESHOLD = 1_000_000_000

AUTH_URL = "https://users.roblox.com/v1/users/authenticated"
REPORT_URL = "https://apis.roblox.com/abuse-reporting/v1/abuse-report"
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
    if stripped.startswith("#HttpOnly_"):
        parts = stripped[len("#HttpOnly_"):].split("\t")
        if len(parts) >= 7 and parts[-2].strip() == ".ROBLOSECURITY":
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

    def cookie_header(self) -> str:
        with self._lock:
            return self.header

    def set_value(self, new_value: str) -> None:
        with self._lock:
            if new_value == self.value:
                return
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
            self.remaining = 0
            self.reset_at = reset_epoch if reset_epoch and reset_epoch > now else now + RATE_LIMIT_SLEEP

    def update_from_response(self, r: requests.Response) -> None:
        remaining = first_int(header_value(r, "x-ratelimit-remaining", "x-rate-limit-remaining"))
        reset_at = rate_limit_reset(r)
        with self._lock:
            if remaining is not None:
                self.remaining = min(self.remaining, max(0, remaining))
            if reset_at is not None:
                self.reset_at = max(reset_at, time.time())
        new_value = r.cookies.get(".ROBLOSECURITY")
        if new_value:
            self.set_value(new_value.strip())


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
                now = time.time()
                n = len(self._valid)
                for _ in range(n):
                    c = self._valid[self._rr % n]
                    self._rr += 1
                    if c.try_consume(now):
                        return c
                self._valid = [c for c in self._valid if not c.is_invalid()]
                if not self._valid:
                    return None
                soonest = min(c.next_reset() for c in self._valid)
                delay = max(0.2, min(LEASE_POLL, soonest - now))
                if stop_event.wait(timeout=delay):
                    return None

    def refill(self) -> None:
        with self._cond:
            self._valid = [c for c in self._valid if not c.is_invalid()]
            self._cond.notify_all()


def load_cookies(path: str) -> list[Cookie]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        sys.exit(f"[-] {path} not found")
    parsed = [p for p in (parse_cookie_line(l) for l in lines) if p and p["value"]]
    if not parsed:
        sys.exit(f"[-] No usable .ROBLOSECURITY values in {path}")
    return [Cookie(p["header"], p["value"]) for p in parsed]


def validate_cookie(cookie: Cookie) -> bool:
    try:
        r = get_session().get(AUTH_URL, headers=base_headers(cookie.cookie_header()), timeout=VALIDATION_TIMEOUT)
    except requests.RequestException:
        return False
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
        with open(path, "r", encoding="utf-8") as f:
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


def load_reported_ids(path: str) -> set[int]:
    reported: set[int] = set()
    if not os.path.exists(path):
        return reported
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped.isascii() and stripped.isdigit():
                reported.add(int(stripped))
    return reported


class ReportedLog:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._fh = open(path, "a", encoding="utf-8", buffering=1)

    def record(self, uid: int) -> None:
        line = f"{uid}\n"
        with self._lock:
            self._fh.write(line)
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
                os.fsync(self._fh.fileno())
            finally:
                self._fh.close()


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
    try:
        r = get_session().post(REPORT_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        return None, e
    if r.status_code == 403:
        token = r.headers.get("x-csrf-token")
        if token:
            cookie.csrf_token = token
            headers["x-csrf-token"] = token
            try:
                r = get_session().post(REPORT_URL, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
            except requests.RequestException as e:
                return None, e
    return r, None


def requeue(target, retry_q, retry_counts, retry_lock, stats):
    with retry_lock:
        count = retry_counts.get(target, 0) + 1
        if count > MAX_TARGET_RETRIES:
            retry_counts.pop(target, None)
            dropped = True
        else:
            retry_counts[target] = count
            dropped = False
    if dropped:
        log.warning("dropping %s after %d failures", target, count)
        stats.bump("dropped")
        return False
    try:
        retry_q.put_nowait(target)
    except Exception:
        stats.bump("dropped")
        return False
    stats.bump("retried")
    return True


def reporter_worker(
    name, report_q, retry_q, pool, stop_event, stats,
    category, surface, comment, retry_counts, retry_lock,
    reported_log, reported_set_lock, reported_set,
):
    while True:
        target = None
        from_main = False
        if not stop_event.is_set():
            try:
                target = retry_q.get_nowait()
            except queue.Empty:
                pass
        if target is None and not stop_event.is_set():
            try:
                target = report_q.get(timeout=WORKER_POLL_INTERVAL)
                from_main = True
            except queue.Empty:
                if stop_event.is_set():
                    return
                continue
        if target is None:
            return

        try:
            cookie = pool.lease(stop_event)
            if cookie is None:
                stats.bump("dropped")
                with retry_lock:
                    retry_counts.pop(target, None)
                continue
            r, err = submit_report(cookie, target, category, surface, comment)
            if err is not None:
                log.warning("[%s] %s network error", name, target)
                stats.bump("network_error")
                cookie.refund()
                pool.refill()
                with retry_lock:
                    count = retry_counts.get(target, 0)
                backoff = min(NETWORK_BACKOFF_MAX, NETWORK_BACKOFF_BASE * (count + 1))
                if stop_event.wait(timeout=backoff):
                    with retry_lock:
                        retry_counts.pop(target, None)
                    break
                requeue(target, retry_q, retry_counts, retry_lock, stats)
                continue

            cookie.update_from_response(r)
            pool.refill()

            if r.status_code == 200:
                reported_log.record(target)
                with reported_set_lock:
                    reported_set.add(target)
                with retry_lock:
                    retry_counts.pop(target, None)
                stats.bump("reported")
                log.info("[%s] reported %s (cookie=%s)", name, target, cookie.id)
            elif r.status_code == 429:
                stats.bump("rate_limited")
                cookie.apply_rate_limit(rate_limit_reset(r))
                pool.refill()
                log.warning("[%s] 429 on %s (cookie=%s), requeueing", name, target, cookie.id)
                requeue(target, retry_q, retry_counts, retry_lock, stats)
            elif r.status_code in (401, 403):
                if r.status_code == 401:
                    cookie.set_invalid()
                    pool.refill()
                stats.bump("http_error")
                log.warning("[%s] auth %s on %s (cookie=%s)", name, r.status_code, target, cookie.id)
                requeue(target, retry_q, retry_counts, retry_lock, stats)
            else:
                stats.bump("http_error")
                log.warning("[%s] HTTP %s on %s", name, r.status_code, target)
                requeue(target, retry_q, retry_counts, retry_lock, stats)
        except Exception:
            log.exception("[%s] unhandled error processing %s", name, target)
            if not stop_event.is_set():
                requeue(target, retry_q, retry_counts, retry_lock, stats)
        finally:
            if from_main:
                report_q.task_done()


def deadline_watchdog(deadline: float, stop_event: threading.Event, cap_seconds: int) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            log.warning("runtime cap (%ds) reached; shutting down", cap_seconds)
            stop_event.set()
            return
        if stop_event.wait(timeout=min(5.0, remaining)):
            return


def resolve_config() -> tuple[str, str, str]:
    cat_env = os.environ.get("REPORT_CATEGORY", "").strip()
    surf_env = os.environ.get("REPORT_SURFACE", "").strip()
    comment_env = os.environ.get("REPORT_COMMENT", "")
    category = next((api for _label, api in CATEGORIES if api == cat_env), CATEGORIES[0][1])
    surface = next((api for _label, api in SURFACES if api == surf_env), SURFACES[0][1])
    comment = comment_env[:1000] if comment_env else ""
    return category, surface, comment


def main() -> int:
    parser = argparse.ArgumentParser(description="Submit reports for targets listed in users.txt")
    parser.add_argument("--max-runtime", type=int, default=DEFAULT_MAX_RUNTIME_SECONDS)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    category, surface, comment = resolve_config()
    cat_src = "REPORT_CATEGORY" if os.environ.get("REPORT_CATEGORY", "").strip() else "default"
    surf_src = "REPORT_SURFACE" if os.environ.get("REPORT_SURFACE", "").strip() else "default"
    comment_src = "REPORT_COMMENT" if os.environ.get("REPORT_COMMENT", "") else "default"
    log.info("category=%s (from %s)  surface=%s (from %s)  comment=%s (from %s)",
             category, cat_src, surface, surf_src, "set" if comment else "empty", comment_src)

    cookies = load_cookies(COOKIE_FILE)
    log.info("loaded %d cookie line(s)", len(cookies))
    valid = validate_all_cookies(cookies)
    if not valid:
        sys.exit("[-] No valid cookies remain")

    all_ids = load_user_ids(USERS_FILE)
    already_reported = load_reported_ids(REPORTED_FILE)
    pending = [uid for uid in all_ids if uid not in already_reported]

    log.info("users.txt=%d  already_reported=%d  pending=%d",
             len(all_ids), len(already_reported), len(pending))

    if not pending:
        log.info("no pending targets; exiting")
        return 0

    pool = CookiePool(valid)
    stop_event = threading.Event()

    def _handle_signal(signum, _frame):
        log.warning("received signal %s; shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    start_mono = time.monotonic()
    deadline_mono = start_mono + args.max_runtime

    reported_log = ReportedLog(REPORTED_FILE)
    reported_set: set[int] = set(already_reported)
    reported_set_lock = threading.Lock()

    report_q: queue.Queue = queue.Queue()
    retry_q: queue.Queue = queue.Queue()
    retry_counts: dict[int, int] = {}
    retry_lock = threading.Lock()
    stats = Stats()

    for uid in pending:
        report_q.put(uid)

    report_workers = max(2, min(REPORT_WORKERS_MAX, len(valid)))
    log.info("starting %d worker(s) with %d cookie(s)", report_workers, len(valid))
    reporters = [
        threading.Thread(
            target=reporter_worker,
            args=(
                f"w-{i}", report_q, retry_q, pool, stop_event, stats,
                category, surface, comment, retry_counts, retry_lock,
                reported_log, reported_set_lock, reported_set,
            ),
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
        daemon=True,
        name="watchdog",
    )
    watchdog.start()

    idle_since: float | None = None
    while True:
        if stop_event.is_set():
            break
        if report_q.empty() and retry_q.empty():
            if idle_since is None:
                idle_since = time.monotonic()
            elif time.monotonic() - idle_since > 2.0:
                log.info("all queues drained; shutting down")
                stop_event.set()
                break
        else:
            idle_since = None
        if stop_event.wait(timeout=1.0):
            break

    grace_start = time.monotonic()
    for t in reporters:
        remaining = max(1.0, SHUTDOWN_GRACE - (time.monotonic() - grace_start))
        t.join(timeout=remaining)

    reported_log.close()

    final = stats.merged()
    elapsed = time.monotonic() - start_mono
    print("\n=== summary ===")
    print(f"runtime                 : {elapsed:.1f}s (cap {args.max_runtime}s)")
    print(f"category                : {category}")
    print(f"surface                 : {surface}")
    print(f"pending at start        : {len(pending)}")
    print(f"reports submitted (200) : {final.get('reported', 0)}")
    print(f"rate-limit hits (429)   : {final.get('rate_limited', 0)}")
    print(f"network errors          : {final.get('network_error', 0)}")
    print(f"targets retried         : {final.get('retried', 0)}")
    print(f"auth/http errors        : {final.get('http_error', 0)}")
    print(f"dropped targets         : {final.get('dropped', 0)}")
    print(f"valid cookies at start  : {len(valid)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
