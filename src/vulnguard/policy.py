from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .config import SEVERITIES, Config


class SlaStatus(StrEnum):
    OVERDUE = "overdue"
    DUE_SOON = "due_soon"
    OK = "ok"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def now_utc() -> datetime:
    return datetime.now(UTC)


@dataclass
class Alert:
    repo: str
    number: int
    package: str
    ecosystem: str
    severity: str
    summary: str
    ghsa_id: str
    cve_id: str | None
    manifest_path: str
    patched_version: str | None
    html_url: str
    created_at: datetime
    age_days: int = 0
    days_left: int = 0
    status: SlaStatus = SlaStatus.OK
    fix_pr: DependabotPR | None = None

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> Alert:
        advisory = raw.get("security_advisory") or {}
        vuln = raw.get("security_vulnerability") or {}
        package = vuln.get("package") or (raw.get("dependency") or {}).get("package") or {}
        patched = vuln.get("first_patched_version") or {}
        severity = (advisory.get("severity") or vuln.get("severity") or "low").lower()
        return cls(
            repo=raw["repository"]["name"],
            number=raw["number"],
            package=package.get("name", "unknown"),
            ecosystem=package.get("ecosystem", "unknown"),
            severity=severity if severity in SEVERITIES else "low",
            summary=advisory.get("summary", ""),
            ghsa_id=advisory.get("ghsa_id", ""),
            cve_id=advisory.get("cve_id"),
            manifest_path=(raw.get("dependency") or {}).get("manifest_path", ""),
            patched_version=patched.get("identifier"),
            html_url=raw.get("html_url", ""),
            created_at=parse_time(raw["created_at"]),
        )


@dataclass
class DependabotPR:
    repo: str
    number: int
    title: str
    html_url: str
    created_at: datetime
    age_days: int = 0

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> DependabotPR:
        return cls(
            repo=raw["repository_url"].rstrip("/").rsplit("/", 1)[-1],
            number=raw["number"],
            title=raw["title"],
            html_url=raw["html_url"],
            created_at=parse_time(raw["created_at"]),
        )

    @property
    def packages(self) -> set[str]:
        # "Bump lodash from 4.17.20 to 4.17.21", "Bump the npm group ... with 3 updates"
        return {m.lower() for m in re.findall(r"[Bb]ump (\S+) from", self.title)}


@dataclass
class RepoReport:
    repo: str
    alerts: list[Alert] = field(default_factory=list)
    dependabot_prs: list[DependabotPR] = field(default_factory=list)
    owners: list[str] = field(default_factory=list)

    def by_status(self, status: SlaStatus) -> list[Alert]:
        return [a for a in self.alerts if a.status == status]

    @property
    def overdue(self) -> list[Alert]:
        return self.by_status(SlaStatus.OVERDUE)

    @property
    def due_soon(self) -> list[Alert]:
        return self.by_status(SlaStatus.DUE_SOON)

    def stale_prs(self, stale_days: int) -> list[DependabotPR]:
        return [p for p in self.dependabot_prs if p.age_days >= stale_days]

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for a in self.alerts:
            counts[a.severity] += 1
        return counts

    @property
    def risk_score(self) -> int:
        """Rough ordering key: overdue criticals dominate, then volume."""
        weights = {"critical": 1000, "high": 100, "medium": 10, "low": 1}
        score = 0
        for a in self.alerts:
            score += weights[a.severity] * (3 if a.status == SlaStatus.OVERDUE else 1)
        return score

    @property
    def is_clean(self) -> bool:
        return not self.alerts


def evaluate(
    config: Config,
    raw_alerts: list[dict[str, Any]],
    raw_prs: list[dict[str, Any]],
    repos: list[str],
    now: datetime | None = None,
) -> dict[str, RepoReport]:
    now = now or now_utc()
    reports = {name: RepoReport(repo=name) for name in repos}

    for raw in raw_prs:
        pr = DependabotPR.from_api(raw)
        if pr.repo not in reports:
            continue
        pr.age_days = (now - pr.created_at).days
        reports[pr.repo].dependabot_prs.append(pr)

    for raw in raw_alerts:
        alert = Alert.from_api(raw)
        if alert.repo not in reports:
            continue
        sla = config.sla_days[alert.severity]
        alert.age_days = (now - alert.created_at).days
        alert.days_left = sla - alert.age_days
        if alert.days_left < 0:
            alert.status = SlaStatus.OVERDUE
        elif alert.days_left <= config.due_soon_days:
            alert.status = SlaStatus.DUE_SOON
        report = reports[alert.repo]
        alert.fix_pr = next(
            (p for p in report.dependabot_prs if alert.package.lower() in p.packages), None
        )
        report.alerts.append(alert)

    severity_rank = {s: i for i, s in enumerate(SEVERITIES)}
    for report in reports.values():
        report.alerts.sort(key=lambda a: (a.days_left, severity_rank[a.severity]))
        report.dependabot_prs.sort(key=lambda p: -p.age_days)
    return reports


def parse_codeowners_default(text: str) -> list[str]:
    """Return owners of the catch-all `*` rule (last match wins, like GitHub)."""
    owners: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] in ("*", "/*", "/"):
            owners = [p for p in parts[1:] if p.startswith("@")]
    return owners
