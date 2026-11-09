"""Track Dependabot on the repos a rollout created and print a Markdown report.

Usage: repo_metrics.py REPORT.json [REPORT.json ...] [--wait-timeout 3600]
                       [--settle 180] [--poll 60] [--max-logs 100]

REPORT.json files are the provision.py reports for a rollout. Polls every repo
(batched GraphQL) until each one has a Dependabot alert whose security update has
opened a PR or recorded an error, then waits --settle seconds with no change, or
gives up after --wait-timeout. Then reads each repo's Dependabot runs, jobs and
PRs and reports, per repo, per stack and overall:
  * time to alert        repo pushed -> first Dependabot alert
  * time to security job repo pushed -> first security-update job started
  * time to PR           repo pushed -> security update PR opened
  * queue / execution    Dependabot job created -> started -> completed
  * failure rate         runs whose conclusion is not success/skipped/neutral
  * registry latency     proxy request -> response per registry host, from job logs
  * repos with an alert but no security PR, with Dependabot's error if any
GH_TOKEN needs read access to the repos' Dependabot alerts, Actions and PRs.
"""

import argparse
import collections
import datetime as dt
import json
import pathlib
import re
import sys
import time
import urllib.parse

import gh
from stacks import STACKS, repo_key

OK_CONCLUSIONS = {"success", "skipped", "neutral"}
PENDING = {"queued", "in_progress", "waiting", "pending", "requested"}
NON_REGISTRY_HOSTS = {"github.com", "api.github.com", "codeload.github.com"}
PROXY_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+)Z\s+proxy \| \S+ \S+ \[(?P<rid>\d+)\] "
    r"(?P<what>[A-Z]+|\d{3}) (?P<url>\S+)(?P<rest>.*)$"
)
BATCH = 20
LIST_LIMIT = 50
COMMENT_LIMIT = 60000

REPO_QUERY = """
  {alias}: repository(owner: "{owner}", name: "{name}") {{
    vulnerabilityAlerts(first: 20) {{ nodes {{
      number createdAt state
      securityAdvisory {{ ghsaId severity }}
      securityVulnerability {{ package {{ name }} }}
      dependabotUpdate {{ pullRequest {{ number url createdAt }} error {{ title body errorType }} }}
    }} }}
    pullRequests(first: 20, orderBy: {{field: CREATED_AT, direction: ASC}}) {{ nodes {{
      number url title createdAt state author {{ login }}
    }} }}
  }}"""


def ts(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def secs(start, end):
    return (ts(end) - ts(start)).total_seconds() if start and end else None


def load_reports(paths):
    stacks = []
    for p in paths:
        stacks.append(json.loads(pathlib.Path(p).read_text()))
    return sorted(stacks, key=lambda s: list(STACKS).index(s["stack"]) if s["stack"] in STACKS else 99)


def snapshot(repos, graphql=gh.graphql):
    """{repo: {"alerts": [...], "prs": [...]}} for every repo, via batched GraphQL."""
    out = {}
    for i in range(0, len(repos), BATCH):
        chunk = repos[i:i + BATCH]
        body = "".join(REPO_QUERY.format(alias=f"r{j}", owner=r.split("/")[0], name=r.split("/")[1])
                       for j, r in enumerate(chunk))
        data = graphql("query {" + body + "\n}")
        for j, r in enumerate(chunk):
            node = data.get(f"r{j}") or {}
            out[r] = {
                "alerts": (node.get("vulnerabilityAlerts") or {}).get("nodes") or [],
                "prs": [p for p in (node.get("pullRequests") or {}).get("nodes") or []
                        if (p.get("author") or {}).get("login") in ("dependabot", "dependabot[bot]")],
            }
    return out


def repo_settled(state):
    alerts = state["alerts"]
    return bool(alerts) and all(a.get("state") != "OPEN"
                                or (a.get("dependabotUpdate") or {}).get("pullRequest")
                                or (a.get("dependabotUpdate") or {}).get("error") for a in alerts)


def wait(repos, wait_timeout, settle, poll, graphql=gh.graphql, clock=time.monotonic, sleep=time.sleep):
    start = clock()
    last, last_change = None, start
    while True:
        snap = snapshot(repos, graphql)
        now = clock()
        if snap != last:
            last, last_change = snap, now
        done = sum(repo_settled(s) for s in snap.values())
        if done == len(repos) and now - last_change >= settle:
            return snap, "done"
        if now - start >= wait_timeout:
            return snap, "timeout"
        detail = ", ".join(f"{r.split('/')[-1]}: {len(s['alerts'])} alerts {len(s['prs'])} PRs"
                           for r, s in list(snap.items())[:10])
        print(f"[{int(now - start)}s] {done}/{len(repos)} repos have alert + security update outcome ({detail})",
              file=sys.stderr, flush=True)
        sleep(poll)


def registry_requests(log_text):
    """Yield (host, seconds, cached) for each registry request in a Dependabot job log."""
    started = {}
    for line in log_text.splitlines():
        m = PROXY_LINE.match(line)
        if not m:
            continue
        host = urllib.parse.urlsplit(m["url"]).hostname
        if not host or host in NON_REGISTRY_HOSTS:
            continue
        key = (m["rid"], m["url"])
        when = dt.datetime.fromisoformat(m["ts"][:26])
        if not m["what"].isdigit():
            started[key] = when
        elif key in started:
            yield host, (when - started.pop(key)).total_seconds(), "(cached)" in m["rest"]


def run_kind(name):
    if name.startswith("Configured Graph Update") or "Graph Update" in name:
        return "graph"
    if re.search(r" for \S+", name):
        return "security"
    return "version"


def collect_runs(repo, log_budget, api=gh.api):
    """Dependabot runs of a repo with queue/exec time and registry requests. log_budget: [remaining]."""
    data = api(f"repos/{repo}/actions/runs?event=dynamic&per_page=100")
    rows = []
    for run in sorted(data.get("workflow_runs", []), key=lambda r: r["created_at"]):
        if run["actor"]["login"] != "dependabot[bot]":
            continue
        jobs = api(f"repos/{repo}/actions/runs/{run['id']}/jobs").get("jobs", [])
        queue = exe = 0.0
        first_start = None
        requests = []
        for job in jobs:
            if job.get("started_at"):
                queue += secs(job["created_at"], job["started_at"])
                first_start = min(filter(None, [first_start, job["started_at"]]))
            if job.get("started_at") and job.get("completed_at"):
                exe += secs(job["started_at"], job["completed_at"])
            if log_budget[0] > 0 and job.get("status") == "completed":
                log_budget[0] -= 1
                try:
                    requests += list(registry_requests(api(f"repos/{repo}/actions/jobs/{job['id']}/logs", raw=True)))
                except gh.GhError:
                    pass
        conclusion = run["conclusion"] or run["status"]
        rows.append({
            "name": run["name"], "url": run["html_url"], "kind": run_kind(run["name"]),
            "conclusion": conclusion, "pending": run["status"] != "completed",
            "failed": run["status"] == "completed" and run["conclusion"] not in OK_CONCLUSIONS,
            "created_at": run["created_at"], "started_at": first_start,
            "queue": queue, "exec": exe, "requests": requests,
        })
    return rows


def summarize_repo(prov, state, runs):
    """One row of per-repo metrics."""
    pushed = prov.get("pushed_at")
    alerts = sorted(state.get("alerts", []), key=lambda a: a["createdAt"])
    alert = alerts[0] if alerts else None
    update = (alert or {}).get("dependabotUpdate") or {}
    pr = update.get("pullRequest")
    security_runs = [r for r in runs if r["kind"] == "security" and r["started_at"]]
    first_job = min((r["started_at"] for r in security_runs), default=None)
    other_prs = [p for p in state.get("prs", []) if not pr or p["number"] != pr["number"]]
    return {
        "repo": prov["repo"], "name": prov["name"], "url": prov["url"], "stack": prov["stack"],
        "dependency": prov["dependency"], "lockfile": prov.get("lockfile"), "error": prov.get("error"),
        "nudged": bool(prov.get("nudged_at")),
        "alerts": len(alerts),
        "alert": alert and {"number": alert["number"], "ghsa": alert["securityAdvisory"]["ghsaId"],
                            "severity": alert["securityAdvisory"]["severity"].lower(),
                            "url": f"{prov['url']}/security/dependabot/{alert['number']}"},
        "pr": pr and {"number": pr["number"], "url": pr["url"]},
        "update_error": update.get("error"),
        "version_prs": len(other_prs),
        "t_alert": secs(pushed, alert and alert["createdAt"]),
        "t_job": secs(pushed, first_job),
        "t_pr": secs(pushed, pr and pr["createdAt"]),
        "runs": runs,
    }


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    return s[min(len(s) - 1, max(0, round(p / 100 * len(s) + 0.5) - 1))]


def fmt_s(v):
    if v is None:
        return "–"
    if v < 1:
        return f"{v * 1000:.0f} ms"
    return f"{v:.1f} s" if v < 120 else f"{v / 60:.1f} min"


def stats_row(label, values):
    values = [v for v in values if v is not None]
    avg = sum(values) / len(values) if values else None
    return (f"| {label} | {len(values)} | {fmt_s(avg)} | {fmt_s(pct(values, 50))} | "
            f"{fmt_s(pct(values, 95))} | {fmt_s(max(values) if values else None)} |")


def rate(n, d):
    return f"{n / d:.0%}" if d else "–"


def capped(lines, limit):
    """Shorten long lists in the issue comment; the full report keeps them all."""
    if limit < 10 ** 9 and len(lines) > LIST_LIMIT:
        return lines[:LIST_LIMIT] + [f"- … and {len(lines) - LIST_LIMIT} more (see the workflow run summary)"]
    return lines


def render(rows, state, wait_note="", limit=COMMENT_LIMIT):
    ok = [r for r in rows if not r["error"]]
    runs = [run for r in rows for run in r["runs"]]
    completed = [x for x in runs if not x["pending"]]
    failed = [x for x in completed if x["failed"]]
    with_alert = [r for r in ok if r["alerts"]]
    with_pr = [r for r in ok if r["pr"]]
    out = ["## Dependabot metrics", ""]
    if state == "timeout":
        out += [f"> Stopped waiting after {wait_note}; repos still without a security update outcome are "
                "listed below, runs still in progress are not counted as failures.", ""]
    out += [
        f"**Repos:** {len(ok)}/{len(rows)} created · **Alerted:** {len(with_alert)}/{len(ok)} · "
        f"**Security PRs:** {len(with_pr)}/{len(ok)} ({rate(len(with_pr), len(ok))}) · "
        f"**Dependabot runs:** {len(runs)} · **Failed:** {len(failed)}/{len(completed)} · "
        f"**Failure rate:** {rate(len(failed), len(completed))} · "
        f"**Nudged:** {sum(bool(r.get('nudged')) for r in ok)}",
        "",
        "| Metric | Count | Avg | p50 | p95 | Max |",
        "|---|---|---|---|---|---|",
        stats_row("Repo pushed → first alert", [r["t_alert"] for r in ok]),
        stats_row("Repo pushed → security job started", [r["t_job"] for r in ok]),
        stats_row("Repo pushed → security PR opened", [r["t_pr"] for r in ok]),
        stats_row("Job queue duration", [x["queue"] for x in runs if x["started_at"]]),
        stats_row("Job execution duration", [x["exec"] for x in completed]),
    ]
    by_host, cached = collections.defaultdict(list), collections.Counter()
    for x in runs:
        for host, s, hit in x["requests"]:
            (cached.update([host]) if hit else by_host[host].append(s))
    out.append(stats_row("Registry download latency", [s for v in by_host.values() for s in v]))

    out += ["", "### By stack", "",
            "| Stack | Dependency | Repos | Lockfile | Alerted | Security PRs | p50 → PR | Runs | Failure rate |",
            "|---|---|---|---|---|---|---|---|---|"]
    for stack in dict.fromkeys(r["stack"] for r in rows):
        rs = [r for r in rows if r["stack"] == stack]
        good = [r for r in rs if not r["error"]]
        sruns = [x for r in rs for x in r["runs"] if not x["pending"]]
        deps = ", ".join(f"`{d}`" for d in dict.fromkeys(r["dependency"] for r in rs))
        out.append(f"| {stack} | {deps} | {len(good)}/{len(rs)} | {sum(bool(r['lockfile']) for r in good)}/{len(good)} | "
                   f"{sum(bool(r['alerts']) for r in good)} | {sum(bool(r['pr']) for r in good)} | "
                   f"{fmt_s(pct([r['t_pr'] for r in good if r['t_pr'] is not None], 50))} | "
                   f"{sum(len(r['runs']) for r in rs)} | {rate(sum(x['failed'] for x in sruns), len(sruns))} |")

    out += ["", "### Registry download latency by host", ""]
    if by_host or cached:
        out += ["| Host | Requests | Avg | p50 | p95 | Max | Cached hits |", "|---|---|---|---|---|---|---|"]
        for host in sorted(set(by_host) | set(cached)):
            out.append(stats_row(f"`{host}`", by_host[host]) + f" {cached[host]} |")
    else:
        out.append("No registry requests found in the job logs.")

    errored = [r for r in rows if r["error"]]
    if errored:
        out += ["", "### Repos that failed to provision", ""]
        out += capped([f"- `{r['repo']}`: {r['error']}" for r in errored], limit)
    no_pr = [r for r in ok if not r["pr"]]
    if no_pr:
        out += ["", "### No security PR", ""]
        lines = []
        for r in no_pr:
            why = ("no Dependabot alert" if not r["alerts"] else
                   f"Dependabot error: **{r['update_error']['title']}**" if r["update_error"] else
                   "alert has no security update yet")
            alert = f" ([alert]({r['alert']['url']}))" if r["alert"] else ""
            lines.append(f"- [{r['name']}]({r['url']}): {why}{alert}")
        out += capped(lines, limit)
    if failed:
        out += ["", "### Failed runs", ""]
        out += capped([f"- [{x['name']}]({x['url']}) ({x['conclusion']})" for x in failed], limit)

    table = ["", "<details><summary>All repos</summary>", "",
             "| Repo | Dependency | Lockfile | Alert | Security PR | → alert | → job | → PR | Runs (failed) | Version PRs |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (r["stack"], repo_key(r["name"]))):
        alert = (f"[{r['alert']['severity']}]({r['alert']['url']})" if r["alert"] else "–")
        pr = f"[#{r['pr']['number']}]({r['pr']['url']})" if r["pr"] else "–"
        nudged = " (nudged)" if r.get("nudged") else ""
        table.append(f"| [{r['name']}]({r['url']}){nudged} | `{r['dependency']}` | {r['lockfile'] or '–'} | {alert} | {pr} | "
                     f"{fmt_s(r['t_alert'])} | {fmt_s(r['t_job'])} | {fmt_s(r['t_pr'])} | "
                     f"{len(r['runs'])} ({sum(x['failed'] for x in r['runs'])}) | {r['version_prs']} |")
    body = "\n".join(out) + "\n"
    tail = ["", "</details>"]
    while table and len(body) + len("\n".join(table + tail)) > limit:
        table.pop()
    if len(table) < len(rows) + 5:
        tail = ["", "_Table truncated; the full table is in the workflow run summary._", "</details>"]
    return body + "\n".join(table + tail) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("reports", nargs="+")
    ap.add_argument("--wait-timeout", type=int, default=3600)
    ap.add_argument("--settle", type=int, default=180)
    ap.add_argument("--poll", type=int, default=60)
    ap.add_argument("--max-logs", type=int, default=100, help="job logs to parse for registry latency")
    ap.add_argument("--json", help="also write per-repo metrics here")
    ap.add_argument("--full", help="also write the untruncated report here (for the run summary)")
    args = ap.parse_args()

    provs = [r for s in load_reports(args.reports) for r in s["repos"]]
    live = [r["repo"] for r in provs if not r.get("error")]
    snap, state = wait(live, args.wait_timeout, args.settle, args.poll) if live else ({}, "done")
    budget = [args.max_logs]
    rows = []
    for p in provs:
        runs = []
        if not p.get("error"):
            try:
                runs = collect_runs(p["repo"], budget)
            except gh.GhError as e:
                print(f"{p['repo']}: {e}", file=sys.stderr)
        rows.append(summarize_repo(p, snap.get(p["repo"], {}), runs))
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(rows, indent=2))
    if args.full:
        pathlib.Path(args.full).write_text(render(rows, state, fmt_s(args.wait_timeout), limit=10 ** 9))
    print(render(rows, state, fmt_s(args.wait_timeout)), end="")


if __name__ == "__main__":
    main()
