from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from typing import Any

from .config import SEVERITIES, Config, load_config
from .enforce import apply_enforce, plan_enforce
from .fixtures import FixtureGitHub
from .github import GitHub, GitHubError
from .nag import nag, post_slack_digest, render_org_summary
from .policy import RepoReport, evaluate, parse_codeowners_default
from .rollout import apply_rollout, plan_rollout

CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


def selected_repos(gh: Any, config: Config, only: list[str] | None = None) -> list[dict]:
    repos = [
        r
        for r in gh.list_repos(config.org)
        if not r.get("archived") and config.repo_selected(r["name"])
    ]
    if only:
        repos = [r for r in repos if r["name"] in only]
    return repos


def resolve_owners(gh: Any, config: Config, repo: str) -> list[str]:
    if repo in config.owners:
        return config.owners[repo]
    for path in CODEOWNERS_PATHS:
        text = gh.get_file(config.org, repo, path)
        if text:
            owners = parse_codeowners_default(text)
            if owners:
                return owners
    return config.default_owners


def collect(gh: Any, config: Config, only: list[str] | None = None) -> dict[str, RepoReport]:
    repos = [r["name"] for r in selected_repos(gh, config, only)]
    reports = evaluate(
        config, gh.list_open_alerts(config.org), gh.list_dependabot_prs(config.org), repos
    )
    for report in reports.values():
        if report.alerts or report.dependabot_prs:
            report.owners = resolve_owners(gh, config, report.repo)
    return reports


def print_table(reports: dict[str, RepoReport], stale_days: int) -> None:
    rows = sorted(
        (r for r in reports.values() if r.alerts or r.dependabot_prs), key=lambda r: -r.risk_score
    )
    if not rows:
        print(f"No open alerts or Dependabot PRs across {len(reports)} repos.")
        return
    header = ["repo", *SEVERITIES, "overdue", "due soon", "stale PRs", "owners"]
    table = [header]
    for r in rows:
        c = r.severity_counts()
        table.append(
            [
                r.repo,
                *(str(c[s]) for s in SEVERITIES),
                str(len(r.overdue)),
                str(len(r.due_soon)),
                str(len(r.stale_prs(stale_days))),
                " ".join(r.owners) or "-",
            ]
        )
    widths = [max(len(row[i]) for row in table) for i in range(len(header))]
    for i, row in enumerate(table):
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)))
        if i == 0:
            print("  ".join("-" * w for w in widths))


def report_json(reports: dict[str, RepoReport]) -> str:
    def encode(o: Any) -> Any:
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return str(o)

    payload = {name: asdict(r) for name, r in sorted(reports.items())}
    return json.dumps(payload, default=encode, indent=2)


def write_step_summary(markdown: str, path: str | None) -> None:
    target = path or os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as f:
            f.write(markdown + "\n")


def cmd_report(gh: Any, config: Config, args: argparse.Namespace) -> int:
    reports = collect(gh, config, args.repo)
    if args.format == "json":
        print(report_json(reports))
    elif args.format == "markdown":
        print(render_org_summary(config.org, reports, config.stale_pr_days))
    else:
        print_table(reports, config.stale_pr_days)
    return 0


def cmd_nag(gh: Any, config: Config, args: argparse.Namespace) -> int:
    reports = collect(gh, config, args.repo)
    actions = nag(gh, config, reports, apply=args.apply)
    prefix = "" if args.apply else "[dry-run] "
    for a in actions:
        if a.kind != "noop":
            print(f"{prefix}{a.repo}: {a.kind} ({a.detail})")
    changed = sum(1 for a in actions if a.kind != "noop")
    print(f"{prefix}{changed} action(s) across {len(reports)} repos.")
    summary = render_org_summary(config.org, reports, config.stale_pr_days)
    write_step_summary(summary, args.summary_file)
    if args.slack:
        webhook = os.environ.get(config.slack_webhook_env)
        if not webhook:
            print(
                f"Skipping Slack digest: ${config.slack_webhook_env} is not set.", file=sys.stderr
            )
        elif args.apply:
            post_slack_digest(webhook, config.org, reports, config.stale_pr_days)
            print("Posted Slack digest.")
        else:
            print("[dry-run] would post Slack digest.")
    return 0


def cmd_rollout(gh: Any, config: Config, args: argparse.Namespace) -> int:
    prefix = "" if args.apply else "[dry-run] "
    for repo in selected_repos(gh, config, args.repo):
        if repo["name"] == config.rollout.workflow_repo:
            continue
        plan = plan_rollout(gh, config, repo)
        if plan.skipped_reason:
            print(f"{prefix}{plan.repo}: skip ({plan.skipped_reason})")
            continue
        if plan.existing_pr:
            print(f"{prefix}{plan.repo}: rollout PR already open: {plan.existing_pr}")
            continue
        files = ", ".join(plan.files)
        if not args.apply:
            print(f"{prefix}{plan.repo}: would open PR adding {files}")
            if args.show:
                for path, content in plan.files.items():
                    print(f"\n--- {path} ---\n{content}")
            continue
        try:
            url = apply_rollout(gh, config, plan)
            print(f"{plan.repo}: opened {url}")
        except GitHubError as e:
            print(f"{plan.repo}: failed: {e}", file=sys.stderr)
    return 0


def cmd_enforce(gh: Any, config: Config, args: argparse.Namespace) -> int:
    repos = selected_repos(gh, config)
    try:
        plan = plan_enforce(gh, config, args.mode, repos)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    verb = "update" if plan.existing_id else "create"
    if args.mode == "status-check":
        print(
            f"Ruleset applies to {len(plan.enrolled)} enrolled repo(s): {', '.join(plan.enrolled)}"
        )
    if not args.apply:
        print(f"[dry-run] would {verb} org ruleset:\n{json.dumps(plan.ruleset, indent=2)}")
        return 0
    apply_enforce(gh, config, plan)
    print(f"{verb.capitalize()}d org ruleset '{plan.ruleset['name']}'.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulgard",
        description="Make your org actually fix vulnerable dependencies.",
    )
    parser.add_argument(
        "--config", default="vulgard.yml", help="config file (default: %(default)s)"
    )
    parser.add_argument("--org", help="GitHub org (overrides config)")
    parser.add_argument(
        "--fixtures", help="read GitHub data from a JSON fixture instead of the API"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_repo_filter(p: argparse.ArgumentParser) -> None:
        p.add_argument("--repo", action="append", help="limit to this repo (repeatable)")

    p = sub.add_parser("report", help="show open alerts and SLA status per repo")
    p.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    add_repo_filter(p)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("nag", help="open/update tracking issues, ping owners, escalate")
    p.add_argument("--apply", action="store_true", help="make changes (default is dry-run)")
    p.add_argument("--slack", action="store_true", help="post an org digest to Slack")
    p.add_argument(
        "--summary-file", help="write markdown summary here (default $GITHUB_STEP_SUMMARY)"
    )
    add_repo_filter(p)
    p.set_defaults(func=cmd_nag)

    p = sub.add_parser("rollout", help="open PRs adding dependabot.yml and the vulgard workflow")
    p.add_argument("--apply", action="store_true", help="open PRs (default is dry-run)")
    p.add_argument("--show", action="store_true", help="print the generated files in dry-run")
    add_repo_filter(p)
    p.set_defaults(func=cmd_rollout)

    p = sub.add_parser("enforce", help="create an org ruleset that makes the check required")
    p.add_argument("--mode", choices=["status-check", "workflow"], default="status-check")
    p.add_argument("--apply", action="store_true", help="write the ruleset (default is dry-run)")
    p.set_defaults(func=cmd_enforce)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config, args.org)
        gh = FixtureGitHub.from_file(args.fixtures) if args.fixtures else GitHub()
        return args.func(gh, config, args)
    except (ValueError, FileNotFoundError, GitHubError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
