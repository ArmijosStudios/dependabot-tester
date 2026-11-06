import json
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

import cleanup  # noqa: E402
import gh  # noqa: E402
import manifests  # noqa: E402
import parse_issue  # noqa: E402
import pick_vulnerable  # noqa: E402
import provision  # noqa: E402
import repo_metrics  # noqa: E402
import stacks  # noqa: E402

BODY = """### Concurrency limit

8

### Tech stacks

- [X] python
- [ ] node
- [x] go
- [X] ruby

### Concurrency per stack

python=10
go: 3

### Dependency per stack

python=httpx@0.27.2
"""


class ParseTests(unittest.TestCase):
    def test_parse(self):
        limit, matrix = parse_issue.parse(BODY)
        self.assertEqual(limit, 8)
        by = {m["stack"]: m for m in matrix}
        self.assertEqual(set(by), {"python", "go", "ruby"})
        self.assertEqual((by["python"]["requested"], by["python"]["count"]), (10, 8))
        self.assertEqual(by["go"]["count"], 3)
        self.assertEqual(by["ruby"]["count"], 8)
        self.assertEqual(by["python"]["dependency"], "httpx@0.27.2")
        self.assertIsNone(by["go"]["dependency"])

    def test_bad_input(self):
        for body in (BODY.replace("\n8\n", "\nlots\n"), BODY.replace("[X]", "[ ]").replace("[x]", "[ ]"),
                     BODY.replace("go: 3", "rust=3"), BODY.replace("\n8\n", "\n500\n").replace("python=10", "python=300")):
            with self.assertRaises(ValueError):
                parse_issue.parse(body)

    def test_registry_per_stack(self):
        body = BODY + "\n### Registry per stack\n\npython=https://pypi.example.com/simple/\n"
        by = {m["stack"]: m for m in parse_issue.parse(body)[1]}
        self.assertEqual(by["python"]["registry"], "https://pypi.example.com/simple")
        self.assertIsNone(by["go"]["registry"])
        self.assertIsNone({m["stack"]: m for m in parse_issue.parse(BODY)[1]}["python"]["registry"])
        for bad in ("python=pypi.example.com", 'python=https://x" y', "rust=https://crates.example.com"):
            with self.assertRaises(ValueError):
                parse_issue.parse(BODY + f"\n### Registry per stack\n\n{bad}\n")

    def test_resolve_only_fills_blanks(self):
        matrix = [{"stack": "python", "dependency": None, "advisory": None},
                  {"stack": "node", "dependency": "x@1", "advisory": None}]
        parse_issue.resolve(matrix, picker=lambda stack: {"dependency": "y==1", "advisory": {"ghsa": "G"}})
        self.assertEqual([m["dependency"] for m in matrix], ["y==1", "x@1"])
        self.assertIsNone(matrix[1]["advisory"])


class NamingTests(unittest.TestCase):
    def test_names(self):
        self.assertEqual(stacks.repo_name("python", 1), "python-01")
        self.assertEqual(stacks.repo_name("go", 150), "go-150")
        self.assertEqual(stacks.repo_index("go", "go-07"), 7)
        self.assertIsNone(stacks.repo_index("go", "go-lang"))
        self.assertIsNone(stacks.repo_index("go", "mongo-01"))
        self.assertEqual(sorted(["node-100", "node-11", "node-99"], key=stacks.repo_key),
                         ["node-11", "node-99", "node-100"])

    def test_next_names_continue_after_highest(self):
        existing = ["python-01", "python-03", "python-extra", "node-09", "celi-ios"]
        self.assertEqual(provision.next_names("python", 2, existing), ["python-04", "python-05"])
        self.assertEqual(provision.next_names("ruby", 2, existing), ["ruby-01", "ruby-02"])
        self.assertEqual(provision.next_names("node", 1, existing), ["node-10"])


class ManifestTests(unittest.TestCase):
    def test_package_files(self):
        self.assertEqual(manifests.package_file("python", "python-01", "requests@2.19.1"), "requests==2.19.1\n")
        self.assertEqual(manifests.package_file("python", "python-01", "django>=2,<3"), "django>=2,<3\n")
        node = json.loads(manifests.package_file("node", "node-01", "@scope/pkg@1.2.3"))
        self.assertEqual((node["name"], node["dependencies"]), ("node-01", {"@scope/pkg": "1.2.3"}))
        self.assertEqual(manifests.package_file("ruby", "ruby-01", "rack@2.0.0"),
                         'source "https://rubygems.org"\n\ngem "rack", "2.0.0"\n')
        go = manifests.package_file("go", "go-01", "github.com/a/b@v1.2.0", "Org")
        self.assertEqual(go, "module github.com/Org/go-01\n\ngo 1.22\n\nrequire github.com/a/b v1.2.0\n")
        with self.assertRaises(ValueError):
            manifests.package_file("go", "go-01", "github.com/a/b")

    def test_dependabot_yml(self):
        for stack, cfg in stacks.STACKS.items():
            text = manifests.dependabot_yml(stack)
            self.assertIn(f'package-ecosystem: "{cfg["ecosystem"]}"', text)
            self.assertIn('directory: "/"', text)
            self.assertEqual(text.count("package-ecosystem"), 1)

    def test_registry_config(self):
        self.assertNotIn("registries", manifests.dependabot_yml("python"))
        for stack, cfg in stacks.STACKS.items():
            text = manifests.dependabot_yml(stack, "https://r.example.com/x")
            self.assertTrue(text.startswith(f"version: 2\nregistries:\n  {stack}:\n    type: {cfg['registry_type']}\n"
                                            '    url: "https://r.example.com/x"\n'))
            self.assertEqual("replaces-base: true" in text, stack != "go")
            self.assertIn(f'directory: "/"\n    registries:\n      - {stack}\n', text)
        url = "https://r.example.com"
        self.assertEqual(manifests.package_file("python", "p", "x==1", registry=url), f"--index-url {url}\nx==1\n")
        self.assertTrue(manifests.package_file("ruby", "r", "rack@2.0.0", registry=url).startswith(f'source "{url}"'))
        self.assertEqual(manifests.registry_files("node", url), {".npmrc": f"registry={url}/\n"})
        self.assertEqual(manifests.registry_files("node", None), {})
        files, _ = provision.build_files("node", "node-01", "lodash@4.17.20", "Org", "u", make_lockfiles=False,
                                         registry=url)
        self.assertIn(".npmrc", files)
        self.assertIn(url, files["README.md"])

    def test_python_needs_no_lockfile(self):
        self.assertEqual(manifests.lockfiles("python", {"requirements.txt": "x==1\n"}, "x==1"), {})


class ProvisionTests(unittest.TestCase):
    def test_provision_one(self):
        calls = []

        def fake_api(path, method="GET", body=None, **kw):
            calls.append((method, path, body))
            return {"created_at": "2026-01-01T00:00:00Z"} if method == "POST" else None

        with mock.patch.object(gh, "api", fake_api), \
                mock.patch.object(provision, "push", return_value="abc123") as push:
            r = provision.provision_one("Org", "python", "python-01", "requests==2.19.1", "7",
                                        "https://x/issues/7", make_lockfiles=False)
        self.assertIsNone(r["error"])
        self.assertEqual(r["sha"], "abc123")
        self.assertEqual([c[:2] for c in calls], [
            ("POST", "orgs/Org/repos"), ("PUT", "repos/Org/python-01/topics"),
            ("PUT", "repos/Org/python-01/vulnerability-alerts"),
            ("PUT", "repos/Org/python-01/automated-security-fixes")])
        self.assertTrue(calls[0][2]["private"])
        self.assertEqual(calls[1][2]["names"], [stacks.TOPIC, "python", "issue-7"])
        files = push.call_args[0][2]
        self.assertEqual(sorted(files), [".github/dependabot.yml", "README.md", "requirements.txt"])

    def test_provision_error_is_recorded(self):
        def fail(path, method="GET", body=None, **kw):
            raise gh.GhError("POST orgs/Org/repos: name already exists")

        with mock.patch.object(gh, "api", fail):
            r = provision.run("Org", "node", 2, "lodash@4.17.20", "1", "", existing=[], make_lockfiles=False)
        self.assertEqual(r["created"], 0)
        self.assertEqual([x["name"] for x in r["repos"]], ["node-01", "node-02"])
        self.assertIn("already exists", r["repos"][0]["error"])


class GhTests(unittest.TestCase):
    def test_retry_on_secondary_rate_limit(self):
        results = [mock.Mock(returncode=1, stdout="", stderr="You have exceeded a secondary rate limit"),
                   mock.Mock(returncode=0, stdout='{"ok": 1}', stderr="")]
        with mock.patch("subprocess.run", side_effect=results):
            self.assertEqual(gh.api("x", sleep=lambda s: None), {"ok": 1})

    def test_paginate_concatenated_pages(self):
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout='[{"a":1}]\n[{"a":2}]', stderr="")):
            self.assertEqual(gh.api("x", paginate=True), [{"a": 1}, {"a": 2}])


class CleanupTests(unittest.TestCase):
    def test_targets_need_topic_and_name(self):
        repos = [
            {"name": "python-01", "full_name": "o/python-01", "topics": [stacks.TOPIC, "issue-3"]},
            {"name": "python-02", "full_name": "o/python-02", "topics": []},
            {"name": "celi-ios", "full_name": "o/celi-ios", "topics": [stacks.TOPIC]},
            {"name": "go-10", "full_name": "o/go-10", "topics": [stacks.TOPIC, "issue-4"]},
            {"name": "go-9", "full_name": "o/go-9", "topics": [stacks.TOPIC, "issue-4"]},
        ]
        self.assertEqual(cleanup.targets(repos), ["o/go-9", "o/go-10", "o/python-01"])
        self.assertEqual(cleanup.targets(repos, ["python"]), ["o/python-01"])
        self.assertEqual(cleanup.targets(repos, issue="4"), ["o/go-9", "o/go-10"])


LOG = """\
2026-11-06T03:53:04.3128843Z   proxy | 2026/11/06 03:53:04 [004] GET https://github.com:443/o/r/info/refs
2026-11-06T03:53:04.4115170Z   proxy | 2026/11/06 03:53:04 [004] 200 https://github.com:443/o/r/info/refs
2026-11-06T03:53:11.8817352Z   proxy | 2026/11/06 03:53:11 [016] GET https://pypi.org:443/pypi/flask/json
2026-11-06T03:53:11.9240214Z   proxy | 2026/11/06 03:53:11 [016] 200 https://pypi.org:443/pypi/flask/json
2026-11-06T03:53:12.9238589Z   proxy | 2026/11/06 03:53:12 [018] GET https://pypi.org:443/pypi/flask/json
2026-11-06T03:53:12.9243110Z   proxy | 2026/11/06 03:53:12 [018] 200 https://pypi.org:443/pypi/flask/json (cached)
"""


def prov(name, stack="python", error=None):
    return {"repo": f"o/{name}", "name": name, "url": f"https://github.com/o/{name}", "stack": stack,
            "dependency": "x==1", "lockfile": None, "error": error, "pushed_at": "2026-01-01T00:00:00Z"}


def alert(created, pr=None, error=None):
    return {"number": 1, "createdAt": created, "state": "OPEN",
            "securityAdvisory": {"ghsaId": "GHSA-1", "severity": "CRITICAL"},
            "securityVulnerability": {"package": {"name": "x"}},
            "dependabotUpdate": {"pullRequest": pr, "error": error} if pr or error else None}


class MetricsTests(unittest.TestCase):
    def test_registry_requests(self):
        got = list(repo_metrics.registry_requests(LOG))
        self.assertEqual([(h, c) for h, _, c in got], [("pypi.org", False), ("pypi.org", True)])
        self.assertAlmostEqual(got[0][1], 0.042286, places=5)

    def test_run_kind(self):
        self.assertEqual(repo_metrics.run_kind("pip in / for monai - Update #1"), "security")
        self.assertEqual(repo_metrics.run_kind("pip in / - Update #1"), "version")
        self.assertEqual(repo_metrics.run_kind("Configured Graph Update: pip in / #1"), "graph")

    def test_wait_until_settled(self):
        pr = {"number": 2, "url": "u", "createdAt": "2026-01-01T00:05:00Z"}
        states = iter([{"alerts": []}, {"alerts": [alert("2026-01-01T00:01:00Z", pr)]}])
        last = [None]

        def graphql(q):
            try:
                last[0] = next(states)
            except StopIteration:
                pass
            node = {"vulnerabilityAlerts": {"nodes": last[0]["alerts"]}, "pullRequests": {"nodes": []}}
            return {"r0": node}

        t = iter(range(0, 10000, 60))
        snap, state = repo_metrics.wait(["o/python-01"], 3600, 100, 60, graphql=graphql,
                                        clock=lambda: next(t), sleep=lambda s: None)
        self.assertEqual(state, "done")
        self.assertEqual(snap["o/python-01"]["alerts"][0]["dependabotUpdate"]["pullRequest"]["number"], 2)

    def test_summarize_and_render(self):
        pr = {"number": 2, "url": "https://github.com/o/python-01/pull/2", "createdAt": "2026-01-01T00:05:00Z"}
        run = {"name": "pip in / for x - Update #1", "url": "u1", "kind": "security", "conclusion": "success",
               "pending": False, "failed": False, "created_at": "2026-01-01T00:02:00Z",
               "started_at": "2026-01-01T00:03:00Z", "queue": 10.0, "exec": 60.0,
               "requests": [("pypi.org", 0.04, False), ("pypi.org", 0.0, True)]}
        bad = dict(run, name="Configured Graph Update: pip in / #2", kind="graph", conclusion="failure",
                   failed=True, url="u2", requests=[])
        rows = [
            repo_metrics.summarize_repo(prov("python-01"), {"alerts": [alert("2026-01-01T00:01:00Z", pr)], "prs": []},
                                        [run, bad]),
            repo_metrics.summarize_repo(prov("python-02"), {"alerts": [alert("2026-01-01T00:02:00Z",
                                        error={"title": "Dependabot can't resolve", "body": "", "errorType": "x"})],
                                        "prs": []}, []),
            repo_metrics.summarize_repo(prov("node-01", "node", error="boom"), {}, []),
        ]
        self.assertEqual((rows[0]["t_alert"], rows[0]["t_job"], rows[0]["t_pr"]), (60.0, 180.0, 300.0))
        md = repo_metrics.render(rows, "done")
        self.assertIn("**Repos:** 2/3 created · **Alerted:** 2/2 · **Security PRs:** 1/2 (50%)", md)
        self.assertIn("**Failed:** 1/2 · **Failure rate:** 50%", md)
        self.assertIn("| Repo pushed → security PR opened | 1 | 5.0 min |", md)
        self.assertIn("| `pypi.org` | 1 | 40 ms | 40 ms | 40 ms | 40 ms | 1 |", md)
        self.assertIn("- [python-02](https://github.com/o/python-02): Dependabot error: **Dependabot can't resolve**", md)
        self.assertIn("- `o/node-01`: boom", md)
        self.assertIn("| [python-01](https://github.com/o/python-01) | `x==1` | – | [critical]", md)
        self.assertIn("| python | `x==1` | 2/2 | 0/2 | 2 | 1 | 5.0 min | 2 | 50% |", md)

    def test_render_truncates_long_tables(self):
        rows = [repo_metrics.summarize_repo(prov(f"python-{i:02d}"), {}, []) for i in range(1, 400)]
        md = repo_metrics.render(rows, "timeout", "1h", limit=20000)
        self.assertLessEqual(len(md), 20100)
        self.assertIn("Table truncated", md)
        self.assertIn("Stopped waiting after 1h", md)


class PickTests(unittest.TestCase):
    def test_pick_prefers_critical_with_fix(self):
        def advisory(name, rng, patched, severity="critical", withdrawn=None):
            return {"ghsa_id": f"GHSA-{name}", "cve_id": None, "severity": severity, "summary": "s",
                    "withdrawn_at": withdrawn, "html_url": "u",
                    "vulnerabilities": [{"package": {"ecosystem": "pip", "name": name},
                                         "vulnerable_version_range": rng, "first_patched_version": patched}]}
        advs = {"critical": [advisory("gone", "< 2", "2", withdrawn="x"), advisory("nofix", "< 2", None),
                             advisory("authlib", "<= 1.8.0", "1.9.0")],
                "high": [advisory("other", "< 5", "5", "high")]}
        got = pick_vulnerable.pick("python", get_advisories=lambda e, s: advs[s],
                                   get_versions=lambda st, n: ["1.7.0", "1.8.0", "1.9.0"])
        self.assertEqual(got["dependency"], "authlib==1.8.0")


if __name__ == "__main__":
    unittest.main()
