# issue-repo-dependency-updater

Open an issue with the **Repo dependency rollout** form and GitHub Actions creates N new repos per
selected tech stack in the organization, each named `<stack>-<NN>`, with a vulnerable dependency
pinned in its package file, a `.github/dependabot.yml`, and Dependabot alerts and security updates
turned on. It then tracks Dependabot on those repos and posts the metrics on the issue.

This is the repo-per-package version of
[issue-dependency-updater](https://github.com/ArmijosStudios/issue-dependency-updater), which edits
`stacks/<stack>/pkg-XX` directories inside one repo instead.

## Setup

1. Add an Actions secret **`ORG_REPO_TOKEN`** (Settings → Secrets and variables → Actions). The
   built-in `GITHUB_TOKEN` can't create or read other repos, so this token does all org work:
   - fine-grained PAT, resource owner the org, **All repositories**, with Administration: read/write,
     Contents: read/write, Dependabot alerts: read, Actions: read, Pull requests: read; or
   - classic PAT with `repo`, `delete_repo` and `workflow`.
2. Make sure the `repo-rollout` label exists (the issue form applies it, and the workflow only runs
   for issues with it): `gh label create repo-rollout`.

## Issue form fields

| Field | Example | Meaning |
|---|---|---|
| Concurrency limit | `10` | Caps every stack's count, and is the matrix `max-parallel` (stack jobs running at once). |
| Tech stacks | `[x] python` `[x] node` | Stacks to create repos for. |
| Concurrency per stack | `python=10`<br>`node=5` | How many repos to create per stack (up to 200). Missing stacks default to the limit. |
| Registry per stack (optional) | `python=https://pypi.example.com/simple`<br>`node=https://npm.example.com` | Registry URL per stack. Stacks left out use the public registry. See below. |
| Dependency per stack (optional) | `python=requests==2.19.1`<br>`node=lodash@4.17.20` | `name@version` for all stacks; Python also accepts pip specifiers. Stacks left out get a vulnerable package (below). |

Example: limit `10`, `python=3`, `node=20` creates `python-01..python-03` and `node-01..node-10`.
Numbering continues after the highest existing repo of that stack, so a second rollout of
`python=2` creates `python-04` and `python-05`. Every repo is brand new, so Dependabot has no earlier
alert or closed PR for its dependency.

### Blank dependency: pick from the GitHub Advisory Database

`scripts/pick_vulnerable.py` searches reviewed, non-withdrawn advisories for the stack's ecosystem
(`pip`, `npm`, `rubygems`, `go`), **critical first, then high**, newest first, and takes the first
package that has a `first_patched_version` and a stable release inside the vulnerable range. The
highest such release is pinned and the issue comment links the GHSA. Try it locally with
`python3 scripts/pick_vulnerable.py python`.

### Custom registry

With `stack=URL` set, that stack's repos get the registry in the package manager config
(`--index-url` in `requirements.txt`, `.npmrc`, the Gemfile `source`, `GOPROXY` for `go get`) and a
`registries:` entry in `dependabot.yml` (`python-index`, `npm-registry`, `rubygems-server`,
`goproxy-server`) that the update uses (`replaces-base: true` except for Go). Lockfiles are generated
against it too. The registry must allow anonymous reads; no credentials are configured. Registry
download latency in the metrics report is broken down by host, so the custom registry shows up there.
The advisory picker still reads versions from the public registry.

## What each repo gets

| File | Content |
|---|---|
| `requirements.txt` / `package.json` / `Gemfile` / `go.mod` | Just the vulnerable dependency |
| Lockfile, when it can be generated | `package-lock.json` (`npm install --package-lock-only`), `Gemfile.lock` (`bundle lock`), `go.sum` (`go get`). Best effort: if resolution fails the repo is pushed without one, and the comment shows which repos have one. Python gets none. |
| `.github/dependabot.yml` | One `/` entry for the stack's ecosystem, weekly, `open-pull-requests-limit: 0` so only security update PRs open (a grouped version-update PR would otherwise bump the package first and pre-empt the security PR). Python and Ruby entries also set `insecure-external-code-execution: allow`; Dependabot only accepts it for `pip`, `bundler` and `mix` |
| `README.md` | Points back to the issue |

The repo is private, gets topics `issue-repo-dependency-updater`, `<stack>` and `issue-<N>`, and
`PUT /vulnerability-alerts` (Dependabot alerts + dependency graph) and
`PUT /automated-security-fixes` (Dependabot security updates) are called before the push (and again
after it). Enabling them only after the push raced Dependabot's handling of the push: about half the
repos got no Dependabot run on push and waited ~30 min for a periodic scan.

Safety net: once all of a stack's repos are pushed, any repo with no Dependabot run 3 minutes after
its push (`provision.py --nudge-after`, 0 turns it off) gets a commit that appends a comment to
`dependabot.yml`, which makes Dependabot rerun. These repos are listed as **Nudged** in the rollout
comment and marked `(nudged)` in the metrics; their times are still measured from the first push.

## Workflows

**Repo dependency rollout** (`repo-rollout.yml`, on issue opened): `parse` reads the form →
`provision` runs one matrix job per stack (`max-parallel` = limit) that creates that stack's repos
one after another (`scripts/provision.py`) → `comment` posts the created repos on the issue and
dispatches **Dependabot metrics**. Bad input gets an error comment and the issue stays open.

**Dependabot metrics** (`dependabot-metrics.yml`) downloads the rollout's per-stack reports and runs
`scripts/repo_metrics.py`. It polls the repos (batched GraphQL) until every repo has an alert whose
security update has a PR or an error, then 3 more minutes with no change (gives up after 60
minutes), reads each repo's Dependabot runs, jobs, logs and PRs, comments the report and closes
the issue.

| Metric | Source |
|---|---|
| Time to alert | push → first Dependabot alert `createdAt` |
| Time to security job | push → first security-update run's job `started_at` (run name `... for <pkg> ...`) |
| Time to PR | push → `alert.dependabotUpdate.pullRequest.createdAt` |
| Queue duration | job `created_at` → `started_at` |
| Execution duration | job `started_at` → `completed_at` |
| Failure rate | runs whose conclusion isn't `success`/`skipped`/`neutral` |
| Registry download latency | Dependabot proxy log lines, request → response per request id, per registry host (GitHub hosts and cached hits excluded). Logs of the first 100 jobs are parsed |
| No security PR | repos with no alert, or an alert with no update yet, or `dependabotUpdate.error` (title shown) |

It shows totals, a per-stack table and a per-repo table. Long lists and the per-repo table are
shortened to fit an issue comment; the full report is in the run summary and the
`dependabot-metrics` artifact (`metrics.json`). Re-run it from the Actions tab with the issue
number and the rollout run id.

**Delete generated repos** (`delete-repos.yml`, manual): deletes only repos this repo's rollouts
created, optionally only some stacks or one issue's repos. A repo is deleted only if it matches
everything `provision.py` stamps on it: a `<stack>-<number>` name, the
`issue-repo-dependency-updater`, `<stack>` and `issue-<N>` topics, the generated description linking
to issue N of this repo (or its old name `issue-repo-dependency-updater`), and not a fork. Anything
else in the org, including repos that only look generated, is left alone and listed as `skipped`.
It is a dry run unless `confirm` is `delete`.

## Layout

```
scripts/
  stacks.py           # stack -> ecosystem + package file, repo naming
  parse_issue.py      # issue form body -> job matrix
  pick_vulnerable.py  # pick a critical/high advisory package when no dependency is given
  manifests.py        # package file, lockfile, dependabot.yml and README for a repo
  provision.py        # create one stack's repos, push files, enable Dependabot
  repo_metrics.py     # wait for Dependabot on the repos, print the Markdown report
  cleanup.py          # delete generated repos
  gh.py               # `gh api` wrapper with rate-limit retries
```

Adding a stack: register it in `scripts/stacks.py`, add a template in `scripts/manifests.py`
(and a lockfile command if it has one), and add it to the form's checkboxes.

## Tests

```
python3 -m unittest discover -s tests
```
