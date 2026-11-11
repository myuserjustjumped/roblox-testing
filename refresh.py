from __future__ import annotations

import base64
import os
import re
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import requests

DEFAULT_PROBE_URL = "https://users.roblox.com/v1/users/authenticated"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
ROBLOSECURITY = "roblosecurity"
COOKIE_NAME = ".ROBLOSECURITY"
DEFAULT_COOKIE_FILE = "cookies.txt"
DEFAULT_API_URL = "https://api.github.com"
DEFAULT_RAW_URL = "https://raw.githubusercontent.com"
API_VERSION = "2022-11-28"
GITHUB_USER_AGENT = "reporter-cookie-refresh/1.0"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

LEGACY_COOKIE_RE = re.compile(
    r"^(_\|WARNING:-DO-NOT-SHARE-THIS\.--Sharing-this-will-allow-someone-to-log-in-"
    r"as-you-and-to-steal-your-ROBUX-and-items\.\|_)(GgIQAQ\.)?([0-9A-F]+)$"
)
VALUE_PATTERNS = (
    re.compile(r"\.?ROBLOSECURITY\s*=\s*([^;\s\"',]+)", re.IGNORECASE),
    re.compile(r"(_\|WARNING:[^;\s\"',]+)"),
)


@dataclass
class Line:
    index: int
    raw: str
    value: str | None = None
    kind: str = "cookie"


@dataclass
class Result:
    line: Line
    status: str = "untouched"
    new_value: str | None = None
    http_status: int | None = None
    note: str = ""
    attempts: int = 0


def log(message: str) -> None:
    print(f"refresh: {message}", flush=True)


def warn(message: str) -> None:
    print(f"::warning title=refresh::{message}", flush=True)


def error(message: str) -> None:
    print(f"::error title=refresh::{message}", flush=True)


def netscape_value(stripped: str) -> str | None:
    body = stripped
    if body.startswith("#HttpOnly_"):
        body = body[len("#HttpOnly_"):]
    parts = body.split("\t")
    if len(parts) >= 7 and parts[-2].strip().lstrip(".").lower() == ROBLOSECURITY:
        value = parts[-1].strip()
        if value:
            return value
    return None


def extract_cookie_value(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None
    value = netscape_value(stripped)
    if value:
        return value
    if stripped.startswith("#"):
        return None
    for pattern in VALUE_PATTERNS:
        match = pattern.search(stripped)
        if match:
            return match.group(1)
    candidate = stripped
    if (
        candidate
        and len(candidate) >= 20
        and not any(ch.isspace() for ch in candidate)
    ):
        return candidate
    return None


def load_lines(raw: str) -> list[Line]:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    raw_lines = text.split("\n")
    while raw_lines and not raw_lines[0].strip():
        raw_lines.pop(0)
    while raw_lines and not raw_lines[-1].strip():
        raw_lines.pop()

    lines: list[Line] = []
    for index, raw_line in enumerate(raw_lines):
        value = extract_cookie_value(raw_line)
        if not raw_line.strip():
            kind = "blank"
        elif value:
            kind = "cookie"
        else:
            kind = "comment"
        lines.append(Line(index=index, raw=raw_line, value=value, kind=kind))
    return lines


def replace_value(line: str, old: str, new: str) -> str:
    if old and old in line:
        return line.replace(old, new, 1)
    replaced, count = re.subn(
        r"(\.?ROBLOSECURITY\s*=\s*)([^;\s\"',]+)",
        lambda match: match.group(1) + new,
        line,
        count=1,
        flags=re.IGNORECASE,
    )
    return replaced if count else line


def apply_rotation(text: str, old: str, new: str) -> str:
    if not old or not new or old == new:
        return text
    output: list[str] = []
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        ending = raw_line[len(line):]
        if extract_cookie_value(line) == old:
            output.append(replace_value(line, old, new) + ending)
        else:
            output.append(raw_line)
    return "".join(output)


def set_cookie_headers(response) -> list[str]:
    values: list[str] = []
    raw = getattr(response, "raw", None)
    headers = getattr(raw, "headers", None)
    if headers is not None:
        for getter in ("getlist", "get_all"):
            function = getattr(headers, getter, None)
            if function is None:
                continue
            try:
                found = function("Set-Cookie")
            except Exception:
                found = None
            if found:
                values.extend(found)
            break
        if not values:
            try:
                items = headers.items()
            except Exception:
                items = ()
            for key, val in items:
                if isinstance(key, str) and key.lower() == "set-cookie":
                    values.append(val)
    if not values:
        single = response.headers.get("Set-Cookie")
        if single:
            values.append(single)
    return [value for value in values if value]


def header_name_value(header: str) -> tuple[str, str]:
    first, _, _ = header.partition(";")
    name, sep, value = first.partition("=")
    if not sep:
        return "", ""
    name = name.strip()
    if name.startswith("#HttpOnly_"):
        name = name[len("#HttpOnly_"):]
    return name.lstrip(".").lower(), value.strip()


def is_deletion(header: str, value: str) -> bool:
    if not value:
        return True
    return "max-age=0" in header.lower().replace(" ", "")


def usable_value(value: str | None) -> bool:
    if not value or len(value) < 20:
        return False
    return not any(ch in value for ch in (";", ",", " ", "\r", "\n"))


_thread_state = threading.local()
_deadline: float | None = None


def http_get(url: str, headers: dict, timeout: float):
    session = getattr(_thread_state, "session", None)
    if session is None:
        session = requests.Session()
        session.trust_env = False
        _thread_state.session = session
    return session.get(url, headers=headers, timeout=timeout, allow_redirects=True)


def past_deadline() -> bool:
    return _deadline is not None and time.monotonic() >= _deadline


def run_probe(result: Result, url: str, timeout: float, retries: int) -> Result:
    try:
        return probe(result, url, timeout, retries)
    finally:
        session = getattr(_thread_state, "session", None)
        if session is not None:
            _thread_state.session = None
            try:
                session.close()
            except Exception:
                pass


def probe(result: Result, url: str, timeout: float, retries: int) -> Result:
    old = result.line.value
    if not old:
        result.status = "error"
        result.note = "no cookie value on line"
        return result
    if past_deadline():
        result.status = "skipped"
        result.note = "REFRESH_MAX_SECONDS deadline reached"
        return result

    headers = {
        "Cookie": f"{COOKIE_NAME}={old}",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": DEFAULT_UA,
    }

    last_error = ""
    for attempt in range(1, retries + 2):
        if past_deadline():
            result.status = "skipped"
            result.note = "REFRESH_MAX_SECONDS deadline reached"
            return result
        result.attempts = attempt
        try:
            response = http_get(url, headers, timeout)
        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt <= retries:
                time.sleep(0.5 * (2 ** attempt))
                continue
            result.status = "error"
            result.note = last_error
            return result

        result.http_status = response.status_code

        rotations: list[str] = []
        saw_deletion = False
        hops = list(getattr(response, "history", None) or []) + [response]
        for hop in hops:
            for header in set_cookie_headers(hop):
                name, value = header_name_value(header)
                if name != ROBLOSECURITY:
                    continue
                if is_deletion(header, value):
                    saw_deletion = True
                    continue
                rotations.append(value)

        if rotations:
            new_value = rotations[-1]
            if not usable_value(new_value):
                result.status = "unchanged"
                result.note = "Set-Cookie value rejected by validation"
                return result
            if new_value == old:
                result.status = "unchanged"
                result.note = "Set-Cookie matched the stored value"
            else:
                result.status = "refreshed"
                result.new_value = new_value
                if len(rotations) > 1:
                    result.note = f"{len(rotations)} Set-Cookie headers, used the last"
            return result

        if response.status_code == 200:
            result.status = "unchanged"
            result.note = (
                "Set-Cookie expired the cookie; left alone"
                if saw_deletion
                else "no Set-Cookie header this time"
            )
            return result

        if response.status_code == 401:
            result.status = "invalid"
            result.note = "HTTP 401 (expired, logged out or revoked)"
            return result

        if response.status_code == 403:
            csrf = response.headers.get("x-csrf-token")
            result.status = "gated"
            result.note = (
                "HTTP 403 with X-CSRF-Token: cookie is valid, not a dead cookie"
                if csrf
                else "HTTP 403 (captcha challenge or missing permission); cookie left alone"
            )
            return result

        if response.status_code == 429 and attempt <= retries:
            last_error = "HTTP 429"
            delay = 0.5 * (2 ** attempt)
            retry_after = response.headers.get("retry-after", "")
            if retry_after.isdigit():
                delay = min(float(retry_after), 30.0)
            time.sleep(delay)
            continue

        if response.status_code >= 500 and attempt <= retries:
            last_error = f"HTTP {response.status_code}"
            time.sleep(0.5 * (2 ** attempt))
            continue

        result.status = "error"
        result.note = f"HTTP {response.status_code}"
        return result

    result.status = "error"
    result.note = last_error or "unknown error"
    return result


class GitHubCookieError(Exception):
    pass


class GitHubCookieStore:
    def __init__(
        self,
        repo: str,
        token: str,
        ref: str = "main",
        path: str = DEFAULT_COOKIE_FILE,
        local_path: str | Path = DEFAULT_COOKIE_FILE,
        api: str = DEFAULT_API_URL,
    ) -> None:
        if not REPO_RE.fullmatch(repo.strip()):
            raise GitHubCookieError("COOKIES_REPO must be in owner/repo form")
        if not token.strip():
            raise GitHubCookieError("COOKIES_PAT is empty or not set")
        self.repo = repo.strip()
        self.token = token.strip()
        self.ref = ref.strip() or "main"
        self.path = path.strip() or DEFAULT_COOKIE_FILE
        self.local_path = Path(local_path)
        self.api = api.rstrip("/")
        self._lock = threading.RLock()
        self._session = requests.Session()
        self._session.trust_env = False

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass

    def _headers(self, accept: str) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": accept,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": GITHUB_USER_AGENT,
        }

    def _raw_url(self) -> str:
        return (
            f"{DEFAULT_RAW_URL}/{self.repo}/"
            f"{quote(self.ref, safe='')}/{quote(self.path, safe='')}"
        )

    def _contents_url(self) -> str:
        return f"{self.api}/repos/{self.repo}/contents/{quote(self.path, safe='')}"

    def read(self) -> str:
        last = ""
        for attempt in range(1, 4):
            try:
                response = self._session.get(
                    self._raw_url(),
                    headers=self._headers("text/plain"),
                    timeout=30,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                last = type(exc).__name__
                if attempt < 3:
                    time.sleep(min(2 ** attempt, 10))
                    continue
                raise GitHubCookieError(f"raw read failed after 3 attempts ({last})") from None
            if response.status_code == 200:
                try:
                    return response.content.decode("utf-8-sig")
                except UnicodeError:
                    raise GitHubCookieError("cookies.txt is not valid UTF-8") from None
            if response.status_code in (401, 403, 404):
                raise GitHubCookieError(
                    f"raw read refused (HTTP {response.status_code}); check PAT, repo and ref"
                )
            last = f"HTTP {response.status_code}"
            if attempt < 3:
                time.sleep(min(2 ** attempt, 10))
        raise GitHubCookieError(f"raw read failed after 3 attempts ({last})")

    def _metadata(self) -> tuple[str, str | None]:
        try:
            response = self._session.get(
                self._contents_url(),
                headers=self._headers("application/vnd.github.object+json"),
                params={"ref": self.ref},
                timeout=30,
            )
        except requests.RequestException as exc:
            raise GitHubCookieError(f"contents read failed ({type(exc).__name__})") from None
        if response.status_code != 200:
            raise GitHubCookieError(f"contents read refused (HTTP {response.status_code})")
        try:
            data = response.json()
        except ValueError:
            raise GitHubCookieError("contents read returned invalid JSON") from None
        if not isinstance(data, dict) or data.get("type") != "file" or not data.get("sha"):
            raise GitHubCookieError("cookies.txt is not a readable file in the cookie repo")
        text = None
        if data.get("encoding") == "base64" and data.get("content"):
            try:
                text = base64.b64decode(data["content"]).decode("utf-8-sig")
            except (ValueError, UnicodeError):
                raise GitHubCookieError("contents read returned invalid file content") from None
        return str(data["sha"]), text

    def _put(self, text: str, sha: str) -> int:
        payload = {
            "message": "chore: update cookies.txt",
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            "sha": sha,
            "branch": self.ref,
        }
        try:
            response = self._session.put(
                self._contents_url(),
                headers=self._headers("application/vnd.github+json"),
                json=payload,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise GitHubCookieError(f"contents write failed ({type(exc).__name__})") from None
        return response.status_code

    def rotate(self, old: str, new: str) -> bool:
        if not old or not new or old == new:
            return False
        with self._lock:
            last = ""
            for attempt in range(1, 6):
                try:
                    sha, remote_text = self._metadata()
                    if remote_text is None:
                        remote_text = self.read()
                    updated = apply_rotation(remote_text, old, new)
                    if updated == remote_text:
                        write_private(self.local_path, remote_text)
                        return False
                    status = self._put(updated, sha)
                    if status in (200, 201):
                        write_private(self.local_path, updated)
                        return True
                    if status in (409, 422):
                        last = f"HTTP {status}"
                        if attempt < 5:
                            time.sleep(min(attempt, 3))
                            continue
                    elif status in (401, 403, 404):
                        raise GitHubCookieError(f"contents write refused (HTTP {status})")
                    else:
                        last = f"HTTP {status}"
                except GitHubCookieError:
                    raise
                except requests.RequestException as exc:
                    last = type(exc).__name__
                if attempt < 5:
                    time.sleep(min(2 ** attempt, 10))
            raise GitHubCookieError(f"cookie update failed after 5 attempts ({last})")


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".refresh-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def write_summary(results: list[Result], extra: list[str]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    counts: dict[str, int] = {}
    for row in results:
        counts[row.status] = counts.get(row.status, 0) + 1
    lines = [
        "### Cookie refresh (.ROBLOSECURITY)",
        "",
        f"- cookies checked: **{len(results)}**",
        f"- rotated from `Set-Cookie`: **{counts.get('refreshed', 0)}**",
        f"- no `Set-Cookie` header (checked again next run): **{counts.get('unchanged', 0)}**",
        f"- expired / invalid (401): **{counts.get('invalid', 0)}**",
        f"- gated (403, cookie left alone): **{counts.get('gated', 0)}**",
        f"- not probed (deadline): **{counts.get('skipped', 0)}**",
        f"- request errors: **{counts.get('error', 0)}**",
        "",
        *extra,
        "",
        "| line | http | outcome | note |",
        "| --- | --- | --- | --- |",
    ]
    for row in results:
        lines.append(
            f"| {row.line.index + 1} | "
            f"{row.http_status if row.http_status is not None else '-'} | "
            f"{row.status} | {row.note.replace('|', '/') or '-'} |"
        )
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError:
        pass


def env_text(name: str, default: str) -> str:
    value = (os.environ.get(name) or "").strip()
    return value or default


def env_number(name: str, default: float, cast):
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return cast(default)
    try:
        return cast(raw)
    except ValueError:
        warn(f"{name}={raw!r} is not a number; falling back to {default}")
        return cast(default)


def env_switch(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def main() -> int:
    repo = env_text("COOKIES_REPO", "")
    token = env_text("COOKIES_PAT", "")
    ref = env_text("COOKIES_REF", "main")
    local = Path(env_text("REFRESH_TXT", env_text("COOKIE_FILE", DEFAULT_COOKIE_FILE)))
    url = env_text("REFRESH_URL", DEFAULT_PROBE_URL)
    workers = max(1, env_number("REFRESH_WORKERS", 10, int))
    timeout = max(1.0, env_number("REFRESH_TIMEOUT", 30.0, float))
    retries = max(0, env_number("REFRESH_RETRIES", 2, int))
    max_seconds = env_number("REFRESH_MAX_SECONDS", 900.0, float)
    dry_run = env_switch("REFRESH_DRY_RUN")

    missing = []
    if not token:
        missing.append("COOKIES_PAT")
    if not repo:
        missing.append("COOKIES_REPO")
    if missing:
        error("missing " + " and ".join(missing))
        return 2

    try:
        store = GitHubCookieStore(repo, token, ref, local_path=local)
    except GitHubCookieError as exc:
        error(str(exc))
        return 2

    try:
        raw_blob = store.read()
    except GitHubCookieError as exc:
        error(f"could not read cookies.txt from GitHub: {exc}")
        store.close()
        return 2

    write_private(local, raw_blob)
    lines = load_lines(raw_blob)
    cookie_lines = [line for line in lines if line.kind == "cookie"]
    if not cookie_lines:
        error("no cookies found in cookies.txt")
        store.close()
        return 1

    log(
        f"{len(cookie_lines)} cookie(s) from {repo}; probing {url} "
        f"with {workers} worker(s)"
    )

    results = [Result(line=line) for line in cookie_lines]
    global _deadline
    started = time.monotonic()
    _deadline = started + max_seconds if max_seconds > 0 else None
    exit_code = 0
    persisted = 0
    persistence_errors = 0

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(run_probe, row, url, timeout, retries) for row in results]
        for future in as_completed(futures):
            try:
                row = future.result()
            except Exception as exc:
                exit_code = 1
                warn(f"cookie probe failed ({type(exc).__name__})")
                continue
            if row.status != "refreshed" or not row.new_value or dry_run:
                continue
            try:
                changed = store.rotate(row.line.value or "", row.new_value)
                if changed:
                    persisted += 1
                else:
                    row.note = "remote cookie already changed; no write needed"
            except GitHubCookieError as exc:
                exit_code = 1
                persistence_errors += 1
                row.status = "error"
                row.note = f"rotation received but GitHub persistence failed: {exc}"
                try:
                    current = local.read_text(encoding="utf-8")
                    write_private(local, apply_rotation(current, row.line.value or "", row.new_value))
                except OSError:
                    pass

    elapsed = time.monotonic() - started
    totals: dict[str, int] = {}
    for row in results:
        totals[row.status] = totals.get(row.status, 0) + 1
    log(
        f"probe round took {elapsed:.1f}s; persisted {persisted}, "
        f"no-header {totals.get('unchanged', 0)}, invalid {totals.get('invalid', 0)}, "
        f"gated {totals.get('gated', 0)}, skipped {totals.get('skipped', 0)}, "
        f"errors {totals.get('error', 0)}"
    )

    for row in results:
        line_number = row.line.index + 1
        if row.status == "refreshed":
            log(f"line {line_number}: new .ROBLOSECURITY received via Set-Cookie")
        elif row.status == "invalid":
            warn(
                f"cookie on line {line_number} is no longer valid (HTTP {row.http_status}); "
                "left as-is, replace it by hand"
            )
        elif row.status == "gated":
            warn(f"cookie on line {line_number}: {row.note}")
        elif row.status == "error":
            warn(f"cookie on line {line_number} probe failed: {row.note}")
        elif row.status == "skipped":
            warn(f"cookie on line {line_number} was not probed: {row.note}")

    legacy = [
        row.line.index + 1
        for row in results
        if row.line.value and LEGACY_COOKIE_RE.match(row.line.value)
    ]
    if legacy:
        warn(
            "cookie(s) on line(s) "
            + ", ".join(str(number) for number in legacy)
            + " still match the legacy hex format Roblox rejected from 2026-05-01; "
              "replace them with freshly minted cookies"
        )

    extra: list[str] = []
    if dry_run:
        extra.append(f"- dry run: {totals.get('refreshed', 0)} rotation(s) not pushed")
    elif persisted:
        extra.append(f"- `cookies.txt` updated via GitHub Contents API ({persisted} persisted)")
    elif persistence_errors:
        extra.append("- `cookies.txt` persistence **failed**")
    else:
        extra.append("- `cookies.txt` unchanged (no rotation header this run)")

    write_summary(results, extra)
    store.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
