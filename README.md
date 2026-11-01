# vulnguard

Org-wide automation that makes teams actually deal with vulnerable dependencies.
Turning on Dependabot isn't enough if nobody merges its PRs. vulnguard covers the rest:

| Problem | What vulnguard does |
|---|---|
| Alerts pile up and nobody owns them | Opens **one tracking issue per repo**, mentions the owners, and **comments when an alert goes past its SLA**. Re-pings on a schedule and **escalates** to security leads when criticals or highs stay overdue. Posts a **Slack digest** ranking the worst repos. |
| Dependabot PRs rot | Dependabot config that **groups minor and patch updates into one PR per ecosystem**, plus a workflow that **auto-approves and auto-merges** them once CI passes. Stale PRs are called out in the tracking issue. |
| New vulnerabilities get merged | A reusable **`dependency-review / review`** check fails any PR that adds a dependency with a known vulnerability, and an **org ruleset** makes it required. |

Everything that writes to GitHub runs as a **dry run by default**. Add `--apply` to make changes.

## How it fits together

```
this repo (acme/vulnguard)
├── .github/workflows/nag.yml                  scheduled: vulnguard nag --apply --slack
├── .github/workflows/dependency-review.yml    reusable PR gate (GitHub or OSV engine)
├── .github/workflows/dependabot-automerge.yml reusable auto-merge for Dependabot PRs
└── .github/workflows/required-dependency-review.yml  for `enforce --mode workflow`

every other repo (installed by `vulnguard rollout`)
├── .github/dependabot.yml          generated from detected ecosystems
└── .github/workflows/vulnguard.yml calls the two reusable workflows above
```

## Try it locally (no token needed)

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync
V="uv run vulnguard --config examples/vulnguard.yml --fixtures examples/demo-org.json"
$V report                    # SLA status per repo
$V report --format markdown  # what goes in the Actions job summary
$V nag                       # what issues/comments/escalations it would make
$V rollout --show            # PRs it would open, with generated files
$V enforce                   # the org ruleset it would create
uv run pytest
```

`examples/demo-org.json` is a fake org. Dates like `"@-19d"` resolve relative to today so
the demo never goes stale.

## Rolling it out to a real org

1. **Put this repo in your org** as `vulnguard`. Under *Settings → Actions → General →
   Access*, allow access from repositories in the organization, so other repos can call
   the reusable workflows.

2. **Create a GitHub App** owned by the org and install it on all repositories, with these
   permissions:
   - Repository: Dependabot alerts (read), Issues (read/write), Contents (read/write),
     Pull requests (read/write), Administration (read/write), Workflows (read/write)
   - Organization: Administration (read/write), needed only for `enforce`

   Save its ID as the Actions variable `VULNGUARD_APP_ID` and its private key as the secret
   `VULNGUARD_APP_PRIVATE_KEY`. Optionally add a Slack incoming webhook as `SLACK_WEBHOOK_URL`.

3. **Edit `vulnguard.yml`**: SLA days, owners, escalation contacts, excluded repos, and
   `rollout.engine` (see the caveats below).

4. **Roll out to repos.** Run with a token that has the permissions above (for example
   `export GITHUB_TOKEN=$(gh auth token)` for an org admin):

   ```bash
   uv run vulnguard --org acme rollout                # review the plan
   uv run vulnguard --org acme rollout --apply        # open PRs; enables alerts, security
                                                      # updates, and auto-merge per repo
   ```

   Re-running is safe: repos that already have the files, or an open rollout PR, are skipped.

5. **Make the check required** once those PRs are merged:

   ```bash
   uv run vulnguard --org acme enforce --apply
   ```

   This creates or updates the org ruleset *"vulnguard: block vulnerable dependencies"*,
   requiring `dependency-review / review` on default branches of repos that have the
   workflow. Re-run it after more rollout PRs merge. On GitHub Enterprise Cloud, use
   `--mode workflow` instead: the ruleset runs `required-dependency-review.yml` on every repo
   directly, with no per-repo files.

6. **Turn on the nag job.** `nag.yml` runs weekdays at 15:00 UTC. Trigger it once manually
   with *apply* unchecked to preview.

## How nagging works

- Each alert gets a deadline: `sla_days[severity]` days after it opened (default: critical 7,
  high 30, medium 90, low 180).
- Each repo with open alerts or stale Dependabot PRs gets one issue labeled `vulnguard`. It
  lists overdue, due-soon, and within-SLA alerts, the patched version, and the Dependabot PR
  that fixes each one.
- Owners come from `owners:` in config, then the `*` rule in `CODEOWNERS`, then
  `default_owners`.
- Comments, which are what notify people, are only posted when:
  - an alert newly passes its deadline,
  - `reminder_interval_days` have passed and something is still overdue or stale, or
  - an alert is more than `escalation.after_days_overdue` past due (each alert escalates once).
- State lives in a hidden HTML comment in the issue body, so the bot needs no database.
- When every alert is resolved, the issue is closed with a thank-you.

To silence an alert legitimately, dismiss it in GitHub with a reason. It stops showing up on
the next run.

## Caveats

- **The `github` engine** (GitHub's dependency-review action) needs the dependency graph,
  which on **private repos requires GitHub Code Security (GHAS)**. Without it, set
  `rollout.engine: osv` to use OSV-Scanner, which works everywhere.
- **Auto-merge** only waits for checks that are *required*. If a repo has no required
  checks, Dependabot PRs merge right away. If PR reviews are required, enable *"Allow GitHub
  Actions to create and approve pull requests"* in the org's Actions settings.
- **Org rulesets** need a GitHub plan that supports them, and `--mode workflow` needs
  Enterprise Cloud.
- The org Dependabot alerts API only returns repos the token can see. Use an org-wide App
  installation.

## Development

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

Code lives in `src/vulnguard/`: `policy.py` (SLA evaluation), `nag.py` (issues, comments,
Slack), `rollout.py` (Dependabot config and workflow generation), `enforce.py` (org
rulesets), `github.py` (REST client), and `fixtures.py` (offline fake used by the demo and
tests).
