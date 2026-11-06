"""Thin `gh api` wrapper with retries for GitHub's secondary rate limits."""

import json
import subprocess
import sys
import time

RETRY_MARKERS = ("secondary rate limit", "rate limit exceeded", "HTTP 502", "HTTP 503", "HTTP 504")


class GhError(Exception):
    pass


def api(path, method="GET", body=None, raw=False, paginate=False, retries=5, wait=60, sleep=time.sleep):
    cmd = ["gh", "api", "-X", method, path]
    if paginate:
        cmd.append("--paginate")
    if body is not None:
        cmd += ["--input", "-"]
    for attempt in range(retries + 1):
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
