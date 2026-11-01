from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from .config import SEVERITIES, Config
from .policy import Alert, RepoReport, SlaStatus, now_utc, parse_time

STATE_RE = re.compile(r"<!-- vulgard-state (\{.*?\}) -->", re.S)
SEVERITY_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "⬜"}


@dataclass
class Action:
    repo: str
    kind: str  # create | update | comment | escalate | close | noop
    detail: str = ""


def read_state(body: str | None) -> dict[str, Any]:
    if not body:
        return {}
    match = STATE_RE.search(body)
    if not match:
        return {}
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return {}


def _alert_line(a: Alert) -> str:
    ident = a.cve_id or a.ghsa_id
    due = f"{-a.days_left}d overdue" if a.days_left < 0 else f"due in {a.days_left}d"
    fix = f"upgrade to `{a.patched_version}`" if a.patched_version else "no patched version yet"
    pr = f" · fix ready in #{a.fix_pr.number}" if a.fix_pr else ""
    return (
        f"- {SEVERITY_ICON[a.severity]} **{a.severity}** [`{a.package}`]({a.html_url}) "
        f"({a.ecosystem}, `{a.manifest_path}`) – {a.summary} [{ident}] · **{due}** · {fix}{pr}"
    )


def render_issue_body(
    report: RepoReport, config: Config, state: dict[str, Any], now: datetime
) -> str:
    counts = report.severity_counts()
    stale = report.stale_prs(config.stale_pr_days)
    lines = [
        f"This repository has **{len(report.alerts)} open Dependabot alert(s)**: "
        + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES if counts[s])
        + ".",
        "",
        "Fix deadlines (days from when the alert opened): "
        + ", ".join(f"{s} **{config.sla_days[s]}d**" for s in SEVERITIES)
        + ".",
    ]
    if report.owners:
        lines += ["", f"Owners: {' '.join(report.owners)}"]

    for title, alerts in (
        ("🚨 Overdue", report.overdue),
        ("⏳ Due soon", report.due_soon),
        ("Within SLA", report.by_status(SlaStatus.OK)),
    ):
        if alerts:
            lines += ["", f"### {title} ({len(alerts)})", *[_alert_line(a) for a in alerts]]

    if report.dependabot_prs:
        lines += ["", f"### Open Dependabot PRs ({len(report.dependabot_prs)})"]
        for p in report.dependabot_prs:
            flag = " ⚠️ stale" if p in stale else ""
            lines.append(f"- #{p.number} {p.title} – open {p.age_days}d{flag}")
        lines += [
            "",
            "Merging these is usually the fastest way to clear the list above. "
            "If one can't be merged, comment on it with the reason, or dismiss the alert "
            "with a justification so it stops showing up here.",
        ]

    lines += [
        "",
        "---",
        f"_Updated by vulgard on {now:%Y-%m-%d %H:%M} UTC. This issue closes itself once "
        "every alert is resolved. Please don't edit it by hand; changes are overwritten._",
        f"<!-- vulgard-state {json.dumps(state, sort_keys=True)} -->",
    ]
    return "\n".join(lines)


def _escalation_targets(report: RepoReport, config: Config) -> list[Alert]:
    esc = config.escalation
    if not esc.mentions:
        return []
    return [
        a
        for a in report.overdue
        if a.severity in esc.severities and -a.days_left >= esc.after_days_overdue
    ]


def plan_repo(
    report: RepoReport,
    config: Config,
    issue: dict[str, Any] | None,
    now: datetime,
) -> tuple[list[Action], str | None, list[str]]:
    """Decide what to do for a repo.

    Returns (actions, new_body, comments). new_body is None if the issue should be closed or
    left untouched.
    """
    prev = read_state(issue["body"] if issue else None)
    stale = report.stale_prs(config.stale_pr_days)

    if report.is_clean and not stale:
        if issue:
            return (
                [Action(report.repo, "close", "all alerts resolved")],
                None,
                ["✅ All Dependabot alerts are resolved. Thanks! Closing this issue."],
            )
        return [Action(report.repo, "noop", "clean")], None, []

    overdue_ids = sorted(a.number for a in report.overdue)
    newly_overdue = [a for a in report.overdue if a.number not in set(prev.get("overdue", []))]
    last_reminder = parse_time(prev["last_reminder"]) if prev.get("last_reminder") else None
    reminder_due = last_reminder is None or (
        (now - last_reminder).days >= config.reminder_interval_days
    )
    escalate = [
        a
        for a in _escalation_targets(report, config)
        if a.number not in set(prev.get("escalated", []))
    ]

    comments: list[str] = []
    actions: list[Action] = []
    mentions = " ".join(report.owners)

    if issue and newly_overdue:
        comments.append(
            f"{mentions} {len(newly_overdue)} alert(s) just went past their fix deadline:\n\n"
            + "\n".join(_alert_line(a) for a in newly_overdue)
        )
        actions.append(Action(report.repo, "comment", f"{len(newly_overdue)} newly overdue"))
    elif issue and reminder_due and (report.overdue or stale):
        parts = []
        if report.overdue:
            parts.append(f"**{len(report.overdue)} overdue alert(s)**")
        if stale:
            parts.append(f"**{len(stale)} Dependabot PR(s) open for {config.stale_pr_days}+ days**")
        comments.append(
            f"{mentions} Reminder: this repo still has {' and '.join(parts)}. "
            "See the list in the issue description."
        )
        actions.append(Action(report.repo, "comment", "periodic reminder"))

    if escalate:
        comments.append(
            f"{' '.join(config.escalation.mentions)} Escalating: these alerts are more than "
            f"{config.escalation.after_days_overdue} days past their deadline.\n\n"
            + "\n".join(_alert_line(a) for a in escalate)
        )
        actions.append(Action(report.repo, "escalate", f"{len(escalate)} alert(s)"))

    reminded = bool(comments) or issue is None
    state = {
        "overdue": overdue_ids,
        "escalated": sorted(
            set(prev.get("escalated", [])) & {a.number for a in report.alerts}
            | {a.number for a in escalate}
        ),
        "last_reminder": now.isoformat() if reminded else prev.get("last_reminder"),
    }
    body = render_issue_body(report, config, state, now)
    if issue is None:
        actions.insert(0, Action(report.repo, "create", f"{len(report.alerts)} alert(s)"))
    elif body != issue.get("body"):
        actions.insert(0, Action(report.repo, "update", f"{len(report.alerts)} alert(s)"))
    return actions, body, comments


def nag(
    gh: Any,
    config: Config,
    reports: dict[str, RepoReport],
    apply: bool,
    now: datetime | None = None,
) -> list[Action]:
    now = now or now_utc()
    label = config.issue.label
    all_actions: list[Action] = []
    for repo, report in sorted(reports.items()):
        issue = gh.find_open_issue(config.org, repo, label)
        actions, body, comments = plan_repo(report, config, issue, now)
        all_actions.extend(actions)
        if not apply:
            continue
        kinds = {a.kind for a in actions}
        if "close" in kinds and issue:
            for c in comments:
                gh.comment_issue(config.org, repo, issue["number"], c)
            gh.update_issue(config.org, repo, issue["number"], state="closed")
            continue
        if body is None:
            continue
        if issue is None:
            gh.ensure_label(config.org, repo, label)
            issue = gh.create_issue(config.org, repo, config.issue.title, body, [label])
        elif "update" in kinds:
            gh.update_issue(config.org, repo, issue["number"], body=body)
        for c in comments:
            gh.comment_issue(config.org, repo, issue["number"], c)
    return all_actions


def render_org_summary(org: str, reports: dict[str, RepoReport], stale_days: int) -> str:
    ranked = sorted(
        (r for r in reports.values() if r.alerts or r.stale_prs(stale_days)),
        key=lambda r: -r.risk_score,
    )
    totals = dict.fromkeys(SEVERITIES, 0)
    for r in reports.values():
        for s, n in r.severity_counts().items():
            totals[s] += n
    overdue = sum(len(r.overdue) for r in reports.values())
    lines = [
        f"## Vulnerability report for `{org}`",
        "",
        f"**{sum(totals.values())} open alerts** across {len(ranked)} of {len(reports)} repos "
        f"({', '.join(f'{totals[s]} {s}' for s in SEVERITIES)}). **{overdue} past deadline.**",
    ]
    if not ranked:
        lines += ["", "No open alerts. 🎉"]
        return "\n".join(lines)
    lines += [
        "",
        "| Repo | Critical | High | Medium | Low | Overdue | Stale Dependabot PRs |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in ranked:
        c = r.severity_counts()
        lines.append(
            f"| {r.repo} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} "
            f"| {len(r.overdue)} | {len(r.stale_prs(stale_days))} |"
        )
    return "\n".join(lines)


def post_slack_digest(
    webhook_url: str, org: str, reports: dict[str, RepoReport], stale_days: int
) -> None:
    ranked = sorted(
        (r for r in reports.values() if r.overdue or r.stale_prs(stale_days)),
        key=lambda r: -r.risk_score,
    )
    overdue = sum(len(r.overdue) for r in reports.values())
    critical = sum(r.severity_counts()["critical"] for r in reports.values())
    header = (
        f"*Vulnerability digest for {org}*: {overdue} alert(s) past deadline, "
        f"{critical} critical open, across {len(ranked)} repo(s)."
    )
    rows = [
        f"• <https://github.com/{org}/{r.repo}/security/dependabot|{r.repo}>: "
        f"{len(r.overdue)} overdue, {len(r.stale_prs(stale_days))} stale PR(s)"
        + (f" (owners: {', '.join(r.owners)})" if r.owners else "")
        for r in ranked[:15]
    ]
    if len(ranked) > 15:
        rows.append(f"…and {len(ranked) - 15} more.")
    text = header + ("\n" + "\n".join(rows) if rows else "\nNothing overdue. 🎉")
    resp = httpx.post(webhook_url, json={"text": text}, timeout=15)
    resp.raise_for_status()
