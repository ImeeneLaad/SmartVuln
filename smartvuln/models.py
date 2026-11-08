"""Core data model shared by every SmartVuln module.

A :class:`Finding` is the scanner-independent representation of one security
observation. Normalizers fill the *source* fields; the analysis engine fills the
*analysis* fields (correlation, risk, triage). The original scanner record is
kept verbatim in ``raw`` so provenance and evidence are never lost.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 … critical=4


class ScanType(str, Enum):
    SAST = "SAST"
    DAST = "DAST"
    SCA = "SCA"


class ExecStatus(str, Enum):
    """Uniform execution status returned by every scanner adapter."""

    SUCCESS = "success"                      # ran, report parsed, no tool errors
    COMPLETED_WITH_ERRORS = "completed_with_errors"  # report produced but tool reported errors
    FAILED = "failed"                        # no usable report
    TIMEOUT = "timeout"                      # killed after the configured timeout
    SKIPPED = "skipped"                      # disabled or pre-condition not met

    @property
    def produced_report(self) -> bool:
        return self in (ExecStatus.SUCCESS, ExecStatus.COMPLETED_WITH_ERRORS)


class TriageStatus(str, Enum):
    NEEDS_VERIFICATION = "needs_verification"
    LIKELY_DUPLICATE = "likely_duplicate"
    CONFIRMED = "confirmed"            # only set by a human analyst
    FALSE_POSITIVE = "false_positive"  # only set by a human analyst


class CorrelationStatus(str, Enum):
    MULTI_SCANNER = "multi_scanner"        # group spans several tools
    SAME_SCANNER_DUPLICATE = "same_scanner_duplicate"  # several findings, one tool
    UNCORRELATED = "uncorrelated"          # nothing else matched this finding


@dataclass
class Finding:
    # ---- identity & provenance -------------------------------------------------
    scanner: str                 # semgrep | zap | trivy
    scan_type: str               # SAST | DAST | SCA
    rule_id: str                 # scanner rule / plugin / vulnerability id
    title: str
    application: str = "juice-shop"
    category: str = "other"      # normalized vulnerability class (see engine.taxonomy)
    cwe: list[str] = field(default_factory=list)   # e.g. ["CWE-89"]
    cve: list[str] = field(default_factory=list)   # CVE-… / GHSA-… identifiers
    severity: str = "info"
    confidence: str | None = None  # high|medium|low, None = scanner gave no value
    # ---- location ---------------------------------------------------------------
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    url: str | None = None
    http_method: str | None = None
    parameter: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    target: str | None = None    # scanned artifact (image name, lockfile, …)
    # ---- content ----------------------------------------------------------------
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    references: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    exploitability_hint: str | None = None  # only when the source provides one
    detected_at: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    # ---- analysis (filled by the engine) ----------------------------------------
    id: str = ""
    fingerprint: str = ""
    group_id: str = ""
    correlation_status: str = CorrelationStatus.UNCORRELATED.value
    correlation_reasons: list[str] = field(default_factory=list)
    related_ids: list[str] = field(default_factory=list)
    is_group_primary: bool = True
    risk_score: float = 0.0
    priority: str = ""
    risk_factors: list[dict[str, Any]] = field(default_factory=list)
    triage_status: str = TriageStatus.NEEDS_VERIFICATION.value
    triage_reason: str = ""

    # ------------------------------------------------------------------------------
    def compute_fingerprint(self) -> str:
        """Stable identity used to compare successive scans.

        Deliberately excludes timestamps, severity and free text so that a
        severity change is detected as a *change* rather than as new+resolved.
        """
        if self.scan_type == ScanType.SAST.value:
            loc = f"{self.file_path}:{self.line_start}"
        elif self.scan_type == ScanType.DAST.value:
            loc = f"{self.http_method}|{_strip_query(self.url)}|{self.parameter or ''}"
        else:
            # No installed version in the key: a CVE that still applies after an upgrade is the
            # *same* open issue (persistent), not "resolved + new". Severity/version changes are
            # reported by the comparison instead.
            loc = f"{self.package_name}|{self.file_path or ''}|{self.line_start or ''}|{self.target or ''}"
        key = f"{self.scanner}|{self.rule_id}|{loc}"
        self.fingerprint = hashlib.sha256(key.encode()).hexdigest()[:16]
        if not self.id:
            self.id = self.fingerprint
        return self.fingerprint

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        d = asdict(self)
        if not include_raw:
            d.pop("raw", None)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    @property
    def location(self) -> str:
        if self.file_path:
            return f"{self.file_path}:{self.line_start}" if self.line_start else self.file_path
        if self.url:
            return f"{self.http_method or 'GET'} {self.url}"
        if self.package_name:
            return f"{self.package_name}@{self.package_version}"
        return "-"


def _strip_query(url: str | None) -> str:
    if not url:
        return ""
    return url.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"


@dataclass
class ScannerRun:
    """Outcome of one scanner adapter execution (always produced, even on failure)."""

    scanner: str
    scan_type: str
    status: str
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration_s: float = 0.0
    stdout_tail: str = ""
    stderr_tail: str = ""
    raw_report_paths: list[str] = field(default_factory=list)
    error: str = ""
    findings_count: int = 0
    tool_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
