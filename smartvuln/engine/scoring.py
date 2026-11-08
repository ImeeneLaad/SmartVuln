"""Transparent, configurable risk scoring.

score = clamp(0, 100, base(severity|CVSS) x confidence_multiplier + adjustments)

Every term that contributes is recorded in ``Finding.risk_factors`` together
with a human-readable reason, so the dashboard can explain *why* a finding got
its priority. Adjustments are only applied when the scanner (or the correlation
engine) supplied evidence; missing data never produces a bonus or a penalty,
except for the documented neutral multiplier used when no confidence is given.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from ..models import CorrelationStatus, Finding, ScanType, TriageStatus

DEFAULT_SCORING: dict[str, Any] = {
    "severity_points": {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5},
    "use_cvss_for_sca": True,                 # CVSS v3 x 10 replaces severity points when present
    "confidence_multiplier": {"high": 1.0, "medium": 0.85, "low": 0.6, "unknown": 0.85},
    "adjustments": {
        "dast_attack_succeeded": 10,          # ZAP reports an attack payload that triggered the rule
        "rule_likelihood_high": 5,            # Semgrep rule metadata likelihood=HIGH
        "rule_likelihood_low": -5,
        "corroborated_multi_scanner": 10,     # another tool independently reports the issue
        "reachable_http_handler": 5,          # SAST file is an Express route handler (route map)
        "observed_on_deployment": 5,          # DAST finding = observed on the running app
        "non_production_code": -15,           # tests / fixtures / build tooling
    },
    "non_production_patterns": [r"(^|/)test/", r"\.spec\.ts$", r"(^|/)cypress/", r"(^|/)scripts/", r"(^|/)data/static/"],
    "priority_bands": {"P1": 80, "P2": 60, "P3": 35},  # anything below P3 -> P4
}


def merge_config(user: dict[str, Any] | None) -> dict[str, Any]:
    cfg = deepcopy(DEFAULT_SCORING)
    for key, val in (user or {}).items():
        if isinstance(val, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(val)
        else:
            cfg[key] = val
    return cfg


def priority_for(score: float, bands: dict[str, float]) -> str:
    for name in ("P1", "P2", "P3"):
        if score >= bands[name]:
            return name
    return "P4"


def score_finding(f: Finding, cfg: dict[str, Any], handler_files: set[str] | None = None) -> Finding:
    factors: list[dict[str, Any]] = []
    adj = cfg["adjustments"]

    # 1. base -----------------------------------------------------------------------
    if f.scan_type == ScanType.SCA.value and cfg.get("use_cvss_for_sca") and f.cvss_score is not None:
        base = float(f.cvss_score) * 10
        factors.append({"factor": "base", "value": base,
                        "reason": f"CVSS v3 base score {f.cvss_score} from the advisory (x10)"})
    else:
        base = float(cfg["severity_points"].get(f.severity, 5))
        factors.append({"factor": "base", "value": base, "reason": f"scanner severity '{f.severity}'"})

    # 2. confidence -----------------------------------------------------------------
    conf_key = f.confidence if f.confidence in cfg["confidence_multiplier"] else "unknown"
    mult = float(cfg["confidence_multiplier"][conf_key])
    factors.append({"factor": "confidence", "value": f"x{mult}",
                    "reason": (f"scanner confidence '{f.confidence}'" if f.confidence else
                               "scanner provides no confidence value - neutral multiplier, NOT evidence")})
    score = base * mult

    def add(name: str, reason: str) -> None:
        nonlocal score
        pts = float(adj.get(name, 0))
        if pts:
            score += pts
            factors.append({"factor": name, "value": f"{pts:+g}", "reason": reason})

    # 3. exploitability (only from scanner evidence) ----------------------------------
    if f.scan_type == ScanType.DAST.value and f.exploitability_hint == "active attack payload succeeded":
        add("dast_attack_succeeded", "ZAP recorded an attack payload that triggered this rule")
    if f.exploitability_hint and "likelihood: high" in f.exploitability_hint:
        add("rule_likelihood_high", "rule author rates exploitation likelihood HIGH")
    elif f.exploitability_hint and "likelihood: low" in f.exploitability_hint:
        add("rule_likelihood_low", "rule author rates exploitation likelihood LOW")

    # 4. exposure / context -----------------------------------------------------------
    if f.correlation_status == CorrelationStatus.MULTI_SCANNER.value:
        add("corroborated_multi_scanner", "independently reported by more than one scanner")
    if f.scan_type == ScanType.SAST.value and handler_files and f.file_path in handler_files:
        add("reachable_http_handler", f"{f.file_path} is an Express route handler (route map)")
    if f.scan_type == ScanType.DAST.value:
        add("observed_on_deployment", "observed on the running application")
    if f.file_path and any(re.search(p, f.file_path) for p in cfg["non_production_patterns"]):
        add("non_production_code", "located in test / fixture / tooling code")

    score = max(0.0, min(100.0, round(score, 1)))
    if f.triage_status == TriageStatus.FALSE_POSITIVE.value:
        factors.append({"factor": "triage", "value": "0", "reason": "analyst marked as false positive"})
        score = 0.0

    f.risk_score = score
    f.priority = priority_for(score, cfg["priority_bands"])
    f.risk_factors = factors
    return f


def score_all(findings: list[Finding], cfg: dict[str, Any] | None = None, handler_files: set[str] | None = None) -> list[Finding]:
    cfg = cfg or DEFAULT_SCORING
    for f in findings:
        score_finding(f, cfg, handler_files)
    return findings
