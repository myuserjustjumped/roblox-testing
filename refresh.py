from __future__ import annotations

import base64
import os
import re
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests

DEFAULT_PROBE_URL = "https://users.roblox.com/v1/users/authenticated"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
ROBLOSECURITY = "roblosecurity"
COOKIE_NAME = ".ROBLOSECURITY"
STAGING_FILE = "cookies.refreshed.txt"
TOKEN_ENV_NAMES = ("COOKIES_PAT", "SECRETS_PAT", "GH_PAT", "PAT_TOKEN", "GITHUB_TOKEN")

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


def extract_cookie_value(line: str) -> str | None:
    for pattern in VALUE_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    candidate = line.strip()
    if (
        candidate
        and len(candidate) >= 20
        and not any(ch.isspace() for ch in candidate)
        and not candidate.startswith("#")
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
        stripped = raw_line.strip()
        if not stripped:
            lines.append(Line(index=index, raw=raw_line, kind="blank"))
        elif stripped.startswith("#"):
            lines.append(Line(index=index, raw=raw_line, kind="comment"))
        else:
            value = extract_cookie_value(stripped)
            lines.append(
                Line(
                    index=index,
                    raw=raw_line,
                    value=value,
                    kind="cookie" if value else "comment",
                )
            )
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


def resolve_token() -> str | None:
    for name in TOKEN_ENV_NAMES:
        token = (os.environ.get(name) or "").strip()
        if token:
            return token
    return None


def push_secret(
    name: str, value: str, token: str, repo: str, api: str, attempts: int = 4
) -> tuple[bool, str]:
    try:
        from nacl import encoding, public
    except ImportError:
        return False, "PyNaCl is not installed (pip install PyNaCl)"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "reporter-refresh-cookie/1.0",
    }

    last = ""
    for attempt in range(1, attempts + 1):
        try:
            key_response = requests.get(
                f"{api}/repos/{repo}/actions/secrets/public-key",
                headers=headers,
                timeout=30,
            )
            if key_response.status_code == 401:
                return False, "PAT rejected (401); check it exists and has not expired"
            if key_response.status_code == 403:
                return False, (
                    "PAT lacks permission (403); needs a classic PAT with 'repo' scope "
                    "or a fine-grained PAT with Secrets: write (GITHUB_TOKEN cannot do this)"
                )
            if key_response.status_code == 404:
                return False, f"repo {repo} not found or not visible to the PAT (404)"
            key_response.raise_for_status()
            key_data = key_response.json()

            sealed = public.SealedBox(
                public.PublicKey(key_data["key"].encode(), encoding.Base64Encoder())
            ).encrypt(value.encode())

            put_response = requests.put(
                f"{api}/repos/{repo}/actions/secrets/{name}",
                headers=headers,
                json={
                    "encrypted_value": base64.b64encode(sealed).decode(),
                    "key_id": key_data["key_id"],
                },
                timeout=30,
            )
            if put_response.status_code in (200, 201, 204):
                return True, f"secret {name} updated (HTTP {put_response.status_code})"
            if put_response.status_code in (401, 403, 404):
                return False, (
                    f"secret update refused (HTTP {put_response.status_code}): "
                    f"{put_response.text[:300]}"
                )
            last = f"HTTP {put_response.status_code}: {put_response.text[:300]}"
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"

        if attempt < attempts:
            time.sleep(min(2 ** attempt, 10))

    return False, f"gave up after {attempts} attempts ({last})"


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
    source_env = env_text("COOKIES_ENV_NAME", "COOKIES_FILE")
    output = Path(env_text("REFRESH_TXT", STAGING_FILE))
    secret_name = env_text("COOKIES_SECRET_NAME", "COOKIES_FILE")
    url = env_text("REFRESH_URL", DEFAULT_PROBE_URL)
    workers = max(1, env_number("REFRESH_WORKERS", 10, int))
    timeout = max(1.0, env_number("REFRESH_TIMEOUT", 30.0, float))
    retries = max(0, env_number("REFRESH_RETRIES", 2, int))
    max_seconds = env_number("REFRESH_MAX_SECONDS", 900.0, float)
    keep_txt = env_switch("REFRESH_KEEP_TXT")
    dry_run = env_switch("REFRESH_DRY_RUN")

    raw_blob = os.environ.get(source_env, "")
    if not raw_blob.strip():
        error(f"environment variable {source_env} is empty or not set")
        return 2

    lines = load_lines(raw_blob)
    cookie_lines = [line for line in lines if line.kind == "cookie"]
    if not cookie_lines:
        error(f"no cookies found in {source_env}")
        return 1

    log(
        f"{len(cookie_lines)} cookie(s) from {source_env}; probing {url} "
        f"with {workers} worker(s)"
    )

    results = [Result(line=line) for line in cookie_lines]
    global _deadline
    started = time.monotonic()
    _deadline = started + max_seconds if max_seconds > 0 else None
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(
            pool.map(
                lambda row: run_probe(row, url, timeout, retries), results
            )
        )
    elapsed = time.monotonic() - started

    rotated = 0
    new_lines: list[str] = []
    by_index = {row.line.index: row for row in results}
    for line in lines:
        row = by_index.get(line.index)
        if row is not None and row.status == "refreshed" and row.new_value:
            new_lines.append(replace_value(line.raw, line.value or "", row.new_value))
            rotated += 1
        else:
            new_lines.append(line.raw)
    secret_text = "\n".join(new_lines) + "\n"

    totals = {status: 0 for status in ("refreshed", "unchanged", "invalid", "gated", "skipped", "error")}
    for row in results:
        totals[row.status] = totals.get(row.status, 0) + 1
    log(
        f"probe round took {elapsed:.1f}s; rotated {totals['refreshed']}, "
        f"no-header {totals['unchanged']}, invalid {totals['invalid']}, "
        f"gated {totals['gated']}, skipped {totals['skipped']}, errors {totals['error']}"
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

    staging = Path(output)
    write_private(staging, secret_text)
    log(f"wrote {staging} ({len(secret_text.splitlines())} line(s))")

    extra: list[str] = []
    exit_code = 0

    if not rotated:
        log(f"nothing to rotate; {secret_name} left untouched")
        extra.append(f"- `{secret_name}` unchanged (no rotation header this run)")
    elif dry_run:
        log(f"dry run: would push {staging} to secret {secret_name}")
        extra.append(f"- dry run: {rotated} rotation(s) not pushed")
    else:
        token = resolve_token()
        repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
        api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
        missing = []
        if not token:
            missing.append("a PAT (COOKIES_PAT)")
        if not repo:
            missing.append("GITHUB_REPOSITORY")
        if missing:
            error("cannot update the secret: missing " + " and ".join(missing))
            exit_code = 2
        else:
            staged_text = staging.read_text(encoding="utf-8")
            size = len(staged_text.encode())
            if size > 46000:
                warn(f"cookie blob is {size} bytes; GitHub's secret limit is 48 KB")
            ok, message = push_secret(secret_name, staged_text, token, repo, api)
            if ok:
                log(message)
                extra.append(f"- `{secret_name}` updated via REST API ({rotated} rotated)")
            else:
                error(f"secret push failed: {message}")
                extra.append(f"- `{secret_name}` push **failed**: {message}")
                exit_code = 1

    if keep_txt:
        log(f"keeping {staging} (REFRESH_KEEP_TXT=1)")
    else:
        try:
            staging.unlink()
            log(f"deleted {staging}")
        except FileNotFoundError:
            pass
        except OSError as exc:
            warn(f"could not delete {staging}: {exc}")

    write_summary(results, extra)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
