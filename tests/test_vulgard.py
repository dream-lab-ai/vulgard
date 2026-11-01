from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from vulgard.cli import collect, main
from vulgard.config import parse_config
from vulgard.enforce import STATUS_CHECK_CONTEXT, plan_enforce
from vulgard.fixtures import FixtureGitHub
from vulgard.nag import nag, plan_repo, read_state
from vulgard.policy import SlaStatus, evaluate, parse_codeowners_default
from vulgard.rollout import (
    DEPENDABOT_PATH,
    WORKFLOW_PATH,
    detect_ecosystems,
    plan_rollout,
    render_caller_workflow,
    render_dependabot_config,
)

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = datetime(2026, 11, 1, 12, tzinfo=UTC)


def iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def alert(number: int, repo: str, severity: str, days_ago: int, package: str = "lodash") -> dict:
    return {
        "number": number,
        "repository": {"name": repo},
        "created_at": iso(days_ago),
        "html_url": f"https://github.com/acme/{repo}/security/dependabot/{number}",
        "dependency": {"package": {"ecosystem": "npm", "name": package}, "manifest_path": "p.json"},
        "security_advisory": {"ghsa_id": f"GHSA-{number}", "summary": "bad", "severity": severity},
        "security_vulnerability": {
            "package": {"ecosystem": "npm", "name": package},
            "first_patched_version": {"identifier": "9.9.9"},
        },
    }


def pr(number: int, repo: str, title: str, days_ago: int) -> dict:
    return {
        "number": number,
        "title": title,
        "html_url": f"https://github.com/acme/{repo}/pull/{number}",
        "repository_url": f"https://api.github.com/repos/acme/{repo}",
        "created_at": iso(days_ago),
    }


@pytest.fixture
def config():
    return parse_config(
        {"org": "acme", "escalation": {"mentions": ["@acme/security"], "after_days_overdue": 7}}
    )


def test_sla_status_by_severity(config):
    reports = evaluate(
        config,
        [
            alert(1, "api", "critical", 8),  # 7d SLA -> 1 day overdue
            alert(2, "api", "high", 27),  # 30d SLA -> 3 days left -> due soon
            alert(3, "api", "medium", 10),  # fine
            alert(4, "other", "critical", 100),  # repo not selected
        ],
        [],
        ["api"],
        NOW,
    )
    by_num = {a.number: a for a in reports["api"].alerts}
    assert set(by_num) == {1, 2, 3}
    assert by_num[1].status == SlaStatus.OVERDUE and by_num[1].days_left == -1
    assert by_num[2].status == SlaStatus.DUE_SOON
    assert by_num[3].status == SlaStatus.OK
    assert [a.number for a in reports["api"].alerts] == [1, 2, 3]


def test_alert_linked_to_dependabot_fix_pr(config):
    reports = evaluate(
        config,
        [alert(1, "api", "high", 1, package="axios")],
        [pr(9, "api", "Bump axios from 1.5.0 to 1.6.0", 1)],
        ["api"],
        NOW,
    )
    assert reports["api"].alerts[0].fix_pr.number == 9


def test_codeowners_catch_all_last_rule_wins():
    text = "* @a\n/docs/ @docs  # docs\n*  @team/x @b\n"
    assert parse_codeowners_default(text) == ["@team/x", "@b"]


def test_unknown_config_keys_rejected():
    with pytest.raises(ValueError, match="Unknown keys"):
        parse_config({"org": "acme", "escalation": {"menshuns": []}})


def plan(config, alerts, issue=None, prs=(), now=NOW):
    report = evaluate(config, alerts, list(prs), ["api"], now)["api"]
    report.owners = ["@acme/api"]
    return plan_repo(report, config, issue, now)


def test_first_run_creates_issue_and_escalates_old_critical(config):
    actions, body, comments = plan(config, [alert(1, "api", "critical", 20)])
    assert [a.kind for a in actions] == ["create", "escalate"]
    assert "@acme/api" in body
    assert len(comments) == 1 and "@acme/security" in comments[0]
    state = read_state(body)
    assert state["overdue"] == [1] and state["escalated"] == [1]


def test_no_repeat_pings_until_reminder_interval(config):
    alerts = [alert(1, "api", "critical", 20)]
    _, body, _ = plan(config, alerts)
    issue = {"number": 5, "body": body}

    # Next day: nothing new, so no comment and no re-escalation.
    actions, body2, comments = plan(config, alerts, issue, now=NOW + timedelta(days=1))
    assert comments == []
    assert "comment" not in {a.kind for a in actions}

    # A week later: periodic reminder.
    issue = {"number": 5, "body": body2}
    actions, _, comments = plan(config, alerts, issue, now=NOW + timedelta(days=7))
    assert len(comments) == 1 and "Reminder" in comments[0]


def test_newly_overdue_alert_triggers_comment(config):
    _, body, _ = plan(config, [alert(1, "api", "high", 25)])
    issue = {"number": 5, "body": body}
    actions, _, comments = plan(
        config, [alert(1, "api", "high", 25)], issue, now=NOW + timedelta(days=6)
    )
    assert "comment" in {a.kind for a in actions}
    assert "just went past their fix deadline" in comments[0]


def test_stale_dependabot_pr_alone_keeps_issue_open(config):
    actions, body, _ = plan(config, [], prs=[pr(3, "api", "Bump x from 1 to 2", 30)])
    assert actions[0].kind == "create"
    assert "stale" in body


def test_clean_repo_closes_issue(config):
    actions, body, comments = plan(config, [], issue={"number": 5, "body": "x"})
    assert [a.kind for a in actions] == ["close"]
    assert body is None and "resolved" in comments[0]


def test_nag_apply_against_fixture():
    config = parse_config(yaml.safe_load((EXAMPLES / "vulgard.yml").read_text()))
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    reports = collect(gh, config)
    assert "sandbox-experiments" not in reports  # excluded
    assert "legacy-billing" not in reports  # archived
    assert reports["web-storefront"].owners == ["@acme/frontend", "@jlee"]  # from CODEOWNERS
    assert reports["payments-api"].owners == ["@acme/payments"]  # from config

    nag(gh, config, reports, apply=True)
    ops = [(op, args[0]) for op, args in gh.writes]
    assert ("create_issue", "payments-api") in ops
    assert ("update_issue", "inventory-service") in ops  # closed
    assert gh.data["issues"]["inventory-service"]["state"] == "closed"

    # Second run right away is idempotent: no new issues or comments.
    gh.writes.clear()
    nag(gh, config, collect(gh, config), apply=True)
    assert not [w for w in gh.writes if w[0] in ("create_issue", "comment_issue")]


def test_detect_ecosystems_skips_vendored_dirs():
    paths = [
        "package.json",
        "web/package.json",
        "node_modules/left-pad/package.json",
        "svc/go.mod",
        "Dockerfile",
        ".github/workflows/ci.yml",
        "App/App.csproj",
    ]
    assert detect_ecosystems(paths) == {
        "docker": ["/"],
        "github-actions": ["/"],
        "gomod": ["/svc"],
        "npm": ["/", "/web"],
        "nuget": ["/App"],
    }


def test_dependabot_config_groups_updates():
    cfg = yaml.safe_load(render_dependabot_config({"npm": ["/", "/web"], "pip": ["/"]}, "weekly"))
    npm, pip = cfg["updates"]
    assert npm["directories"] == ["/", "/web"] and pip["directory"] == "/"
    assert npm["groups"]["minor-and-patch"]["update-types"] == ["minor", "patch"]
    assert npm["groups"]["security"]["applies-to"] == "security-updates"


def test_caller_workflow_is_valid_yaml(config):
    wf = yaml.safe_load(render_caller_workflow(config))
    jobs = wf["jobs"]
    assert jobs["dependency-review"]["uses"].startswith("acme/vulgard/")
    assert "dependabot-automerge" in jobs
    config.rollout.auto_merge = False
    assert "dependabot-automerge" not in yaml.safe_load(render_caller_workflow(config))["jobs"]


def test_rollout_plan_only_adds_missing_files():
    config = parse_config(yaml.safe_load((EXAMPLES / "vulgard.yml").read_text()))
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    repos = {r["name"]: r for r in gh.list_repos("acme")}
    assert set(plan_rollout(gh, config, repos["payments-api"]).files) == {
        DEPENDABOT_PATH,
        WORKFLOW_PATH,
    }
    assert set(plan_rollout(gh, config, repos["web-storefront"]).files) == {WORKFLOW_PATH}
    assert plan_rollout(gh, config, repos["inventory-service"]).skipped_reason


def test_enforce_status_check_targets_enrolled_repos_only():
    config = parse_config(yaml.safe_load((EXAMPLES / "vulgard.yml").read_text()))
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    p = plan_enforce(gh, config, "status-check", gh.list_repos("acme"))
    assert p.enrolled == ["inventory-service"]
    rule = p.ruleset["rules"][0]
    assert rule["parameters"]["required_status_checks"] == [{"context": STATUS_CHECK_CONTEXT}]
    assert p.ruleset["conditions"]["repository_name"]["include"] == ["inventory-service"]


def test_enforce_workflow_mode_uses_repo_id():
    config = parse_config(yaml.safe_load((EXAMPLES / "vulgard.yml").read_text()))
    gh = FixtureGitHub.from_file(EXAMPLES / "demo-org.json")
    p = plan_enforce(gh, config, "workflow", gh.list_repos("acme"))
    wf = p.ruleset["rules"][0]["parameters"]["workflows"][0]
    assert wf["repository_id"] == 107
    assert "vulgard" in p.ruleset["conditions"]["repository_name"]["exclude"]


def test_cli_report_json(capsys):
    code = main(
        [
            "--config",
            str(EXAMPLES / "vulgard.yml"),
            "--fixtures",
            str(EXAMPLES / "demo-org.json"),
            "report",
            "--format",
            "json",
        ]
    )
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["payments-api"]["alerts"][0]["severity"] == "critical"
