"""Analysis pipeline: raw reports -> normalized, correlated, scored, triaged findings."""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Finding
from .correlation import correlate
from .normalize import normalize
from .routemap import Route, build_route_map
from .scoring import merge_config, score_all
from .triage import TriageDecision, apply_decisions

log = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    correlation: dict[str, int] = field(default_factory=dict)
    parse_errors: list[str] = field(default_factory=list)
    routes_mapped: int = 0

    def stats(self) -> dict[str, Any]:
        fs = self.findings
        primary = [f for f in fs if f.is_group_primary]
        return {
            "total": len(fs),
            "unique_issues": len(primary),
            "by_severity": dict(Counter(f.severity for f in fs)),
            "unique_by_severity": dict(Counter(f.severity for f in primary)),
            "by_scanner": dict(Counter(f.scanner for f in fs)),
            "by_scan_type": dict(Counter(f.scan_type for f in fs)),
            "by_priority": dict(Counter(f.priority for f in primary)),
            "by_category": dict(Counter(f.category for f in primary).most_common(12)),
            "by_correlation": dict(Counter(f.correlation_status for f in fs)),
            "by_triage": dict(Counter(f.triage_status for f in fs)),
            "correlation": self.correlation,
            "routes_mapped": self.routes_mapped,
        }


def load_report(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def analyze(raw_reports: dict[str, list[str | Path]], application: str,
            source_root: str | Path | None = None, entrypoint: str = "server.ts",
            scoring_cfg: dict[str, Any] | None = None, line_tolerance: int = 2,
            decisions: dict[str, TriageDecision] | None = None,
            detected_at: str | None = None) -> AnalysisResult:
    result = AnalysisResult()
    findings: list[Finding] = []
    for scanner, paths in raw_reports.items():
        for p in paths:
            try:
                findings.extend(normalize(scanner, load_report(p), application, detected_at))
            except (OSError, ValueError, KeyError, TypeError) as exc:  # bad report must not kill the run
                msg = f"{scanner}: could not parse {Path(p).name}: {exc}"
                log.warning(msg)
                result.parse_errors.append(msg)

    routes: list[Route] = build_route_map(source_root, entrypoint) if source_root else []
    result.routes_mapped = len(routes)
    handler_files = {r.handler_file for r in routes}

    corr = correlate(findings, routes, line_tolerance)
    unique = [f for g in corr.groups.values() for f in g]
    if decisions:
        apply_decisions(unique, decisions)
    score_all(unique, merge_config(scoring_cfg), handler_files)

    unique.sort(key=lambda f: (-f.risk_score, f.group_id, not f.is_group_primary))
    result.findings = unique
    result.correlation = corr.summary()
    return result
