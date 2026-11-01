from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SEVERITIES = ("critical", "high", "medium", "low")

DEFAULT_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


@dataclass
class EscalationConfig:
    after_days_overdue: int = 7
    severities: list[str] = field(default_factory=lambda: ["critical", "high"])
    mentions: list[str] = field(default_factory=list)


@dataclass
class IssueConfig:
    label: str = "vulgard"
    title: str = "Security debt: vulnerable dependencies need attention"


@dataclass
class RolloutConfig:
    workflow_repo: str = "vulgard"
    workflow_ref: str = "main"
    fail_on_severity: str = "high"
    engine: str = "github"
    auto_merge: bool = True
    auto_merge_update_types: list[str] = field(
        default_factory=lambda: ["version-update:semver-patch", "version-update:semver-minor"]
    )
    schedule_interval: str = "weekly"
    branch: str = "vulgard/rollout"


@dataclass
class Config:
    org: str
    include: list[str] = field(default_factory=lambda: ["*"])
    exclude: list[str] = field(default_factory=list)
    sla_days: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SLA_DAYS))
    due_soon_days: int = 5
    stale_pr_days: int = 14
    reminder_interval_days: int = 7
    owners: dict[str, list[str]] = field(default_factory=dict)
    default_owners: list[str] = field(default_factory=list)
    escalation: EscalationConfig = field(default_factory=EscalationConfig)
    issue: IssueConfig = field(default_factory=IssueConfig)
    rollout: RolloutConfig = field(default_factory=RolloutConfig)
    slack_webhook_env: str = "SLACK_WEBHOOK_URL"

    def repo_selected(self, name: str) -> bool:
        if any(fnmatch.fnmatch(name, pat) for pat in self.exclude):
            return False
        return any(fnmatch.fnmatch(name, pat) for pat in self.include)


def _section(raw: dict[str, Any], key: str, cls: type) -> Any:
    data = raw.get(key) or {}
    known = {f for f in cls.__dataclass_fields__}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unknown keys in '{key}': {', '.join(sorted(unknown))}")
    return cls(**data)


def parse_config(raw: dict[str, Any], org_override: str | None = None) -> Config:
    org = org_override or raw.get("org")
    if not org:
        raise ValueError("An 'org' is required (set it in the config file or pass --org)")

    repos = raw.get("repos") or {}
    sla = dict(DEFAULT_SLA_DAYS)
    sla.update({k.lower(): int(v) for k, v in (raw.get("sla_days") or {}).items()})
    bad = set(sla) - set(SEVERITIES)
    if bad:
        raise ValueError(f"Unknown severities in sla_days: {', '.join(sorted(bad))}")

    return Config(
        org=org,
        include=list(repos.get("include") or ["*"]),
        exclude=list(repos.get("exclude") or []),
        sla_days=sla,
        due_soon_days=int(raw.get("due_soon_days", 5)),
        stale_pr_days=int(raw.get("stale_pr_days", 14)),
        reminder_interval_days=int(raw.get("reminder_interval_days", 7)),
        owners={k: list(v) for k, v in (raw.get("owners") or {}).items()},
        default_owners=list(raw.get("default_owners") or []),
        escalation=_section(raw, "escalation", EscalationConfig),
        issue=_section(raw, "issue", IssueConfig),
        rollout=_section(raw, "rollout", RolloutConfig),
        slack_webhook_env=(raw.get("slack") or {}).get("webhook_env", "SLACK_WEBHOOK_URL"),
    )


def load_config(path: str | Path | None, org_override: str | None = None) -> Config:
    raw: dict[str, Any] = {}
    if path is not None:
        p = Path(path)
        if p.exists():
            raw = yaml.safe_load(p.read_text()) or {}
        elif str(path) != "vulgard.yml":
            raise FileNotFoundError(f"Config file not found: {path}")
    return parse_config(raw, org_override)
