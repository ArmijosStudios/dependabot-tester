"""Thin `gh api` wrapper with retries for GitHub's secondary rate limits."""

import json
import subprocess
import sys
import threading
import time

RETRY_MARKERS = ("secondary rate limit", "rate limit exceeded", "HTTP 502", "HTTP 503", "HTTP 504")


class GhError(Exception):
    pass


# REST secondary limit: 900 points/min per token, 5 points per POST/PATCH/PUT/DELETE.
_pace = {"interval": 0.0, "next": 0.0}
_pace_lock = threading.Lock()


def set_mutation_rate(per_minute):
    """Space POST/PATCH/PUT/DELETE calls (across threads) to at most `per_minute`; 0 = unpaced."""
    with _pace_lock:
        _pace["interval"] = 60 / per_minute if per_minute else 0.0


def _throttle(method, sleep):
    if method in ("GET", "HEAD"):
        return
    with _pace_lock:
        if not _pace["interval"]:
            return
        now = time.monotonic()
        at = max(now, _pace["next"])
        _pace["next"] = at + _pace["interval"]
    if at > now:
        sleep(at - now)


def api(path, method="GET", body=None, raw=False, paginate=False, retries=5, wait=60, sleep=time.sleep):
    cmd = ["gh", "api", "-X", method, path]
    if paginate:
        cmd.append("--paginate")
    if body is not None:
        cmd += ["--input", "-"]
    for attempt in range(retries + 1):
        _throttle(method, sleep)
        p = subprocess.run(cmd, input=json.dumps(body) if body is not None else None,
                           capture_output=True, text=True)
        if p.returncode == 0:
            if raw:
                return p.stdout
            if not p.stdout.strip():
                return None
            if paginate:
                return [x for chunk in _json_chunks(p.stdout) for x in (chunk if isinstance(chunk, list) else [chunk])]
            return json.loads(p.stdout)
        err = (p.stderr + p.stdout).strip()
        if attempt < retries and any(m.lower() in err.lower() for m in RETRY_MARKERS):
            print(f"gh api {method} {path}: {err[:200]}; retrying in {wait}s", file=sys.stderr)
            sleep(wait)
            continue
        raise GhError(f"{method} {path}: {err[:500]}")


_seen_errors = set()


def graphql(query, **variables):
    cmd = ["gh", "api", "graphql", "-f", f"query={query}"]
    for k, v in variables.items():
        cmd += ["-F" if isinstance(v, int) else "-f", f"{k}={v}"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        doc = {}
    data = doc.get("data")
    for msg in sorted({e.get("message", str(e)) for e in doc.get("errors") or []}):
        if msg not in _seen_errors:
            _seen_errors.add(msg)
            print(f"graphql error: {msg}", file=sys.stderr)
    if data is None:
        raise GhError(f"graphql: {(p.stderr + p.stdout).strip()[:500]}")
    return data


def _json_chunks(text):
    """`gh api --paginate` concatenates one JSON document per page."""
    dec, pos, text = json.JSONDecoder(), 0, text.strip()
    while pos < len(text):
        obj, end = dec.raw_decode(text, pos)
        yield obj
        pos = end
        while pos < len(text) and text[pos].isspace():
            pos += 1
