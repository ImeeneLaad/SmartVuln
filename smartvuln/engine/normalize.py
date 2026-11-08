"""Convert raw Semgrep / OWASP ZAP / Trivy JSON reports into :class:`Finding` objects.

Rules followed by every normalizer:
* never invent values - a field the scanner does not provide stays ``None``;
* keep the untouched scanner record in ``Finding.raw``;
* mask secret material before it reaches evidence fields, logs or the database.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any, Callable

from ..models import Finding, ScanType
from .taxonomy import categorize, parse_cwes

SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
                    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
ZAP_CONFIDENCE = {"4": "high", "3": "high", "2": "medium", "1": "low", "0": "low"}
TRIVY_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}

# Prefixes introduced by container mount points / image layouts.
_PATH_PREFIXES = ("/src/", "src/", "/juice-shop/", "juice-shop/", "/app/", "./")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_path(path: str | None) -> str | None:
    if not path:
        return None
    p = path.replace("\\", "/")
    changed = True
    while changed:
        changed = False
        for pre in _PATH_PREFIXES:
            if p.startswith(pre):
                p, changed = p[len(pre):], True
    return p.lstrip("/") or None


def strip_html(text: str | None) -> str:
    if not text:
        return ""
    text = re.sub(r"</p>\s*<p>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


_SECRET_RE = re.compile(r"[A-Za-z0-9+/=_]{16,}")


def mask_secret(text: str | None) -> str:
    """Keep the first characters of long token-like strings (letters AND digits), mask the rest.

    Not masked: plain identifiers without digits (Java class names), hyphenated names
    such as container ids (``-`` splits tokens), and URL/file paths whose segments are
    all short. Base64 key material keeps long segments and is still masked.
    """
    if not text:
        return ""

    def _mask(m: re.Match[str]) -> str:
        s = m.group(0)
        if not (re.search(r"\d", s) and re.search(r"[A-Za-z]", s)):
            return s
        if "/" in s and max(len(p) for p in s.split("/")) < 16:
            return s  # a path such as docs/v0.76/guide/scanner/vulnerability
        return s[:6] + "****[masked]"

    return _SECRET_RE.sub(_mask, text)


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ------------------------------------------------------------------------------- Semgrep
def normalize_semgrep(report: dict[str, Any], application: str, detected_at: str | None = None) -> list[Finding]:
    ts = detected_at or now_iso()
    out: list[Finding] = []
    for r in report.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        # Local rule dirs mounted at /rulesN get a "rulesN." prefix from Semgrep -> "custom."
        rule_id = re.sub(r"^rules\d+\.", "custom.", r.get("check_id", "unknown"))
        message = extra.get("message", "") or ""
        cwes = parse_cwes(meta.get("cwe"))
        cves = [c for c in _as_list(meta.get("cve")) if c]
        conf = meta.get("confidence")
        lines = extra.get("lines") or ""
        if lines == "requires login":  # Semgrep OSS hides the snippet without a login
            lines = ""
        category = meta.get("smartvuln_category") or categorize(cwes, rule_id, message)
        evidence = lines.strip()
        if category == "hardcoded-secret":
            evidence = mask_secret(evidence)
        f = Finding(
            scanner="semgrep",
            scan_type=ScanType.SAST.value,
            rule_id=rule_id,
            title=_short_title(rule_id, message),
            application=application,
            category=category,
            cwe=cwes,
            cve=cves,
            severity=SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "low"),
            confidence=str(conf).lower() if conf else None,
            file_path=normalize_path(r.get("path")),
            line_start=(r.get("start") or {}).get("line"),
            line_end=(r.get("end") or {}).get("line"),
            description=message,
            remediation=str(meta.get("remediation") or meta.get("fix") or extra.get("fix") or
                            "Review the flagged code; see the rule references for the secure pattern."),
            evidence=evidence,
            references=[str(x) for x in _as_list(meta.get("references")) + _as_list(meta.get("source"))][:8],
            exploitability_hint=(f"rule likelihood: {meta['likelihood'].lower()}" if meta.get("likelihood") else None),
            detected_at=ts,
            raw=r,
        )
        f.compute_fingerprint()
        out.append(f)
    return out


def _short_title(rule_id: str, message: str) -> str:
    first = re.split(r"(?<=[.!?])\s", message.strip(), maxsplit=1)[0] if message else ""
    if 10 <= len(first) <= 140:
        return first
    return rule_id.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ").capitalize()


# ------------------------------------------------------------------------------- ZAP
def normalize_zap(report: dict[str, Any], application: str, detected_at: str | None = None) -> list[Finding]:
    ts = detected_at or now_iso()
    out: list[Finding] = []
    seen: set[str] = set()
    for site in _as_list(report.get("site")):
        for alert in site.get("alerts", []) or []:
            cwes = parse_cwes(alert.get("cweid"))
            name = alert.get("alert") or alert.get("name") or "ZAP alert"
            plugin = str(alert.get("pluginid", "unknown"))
            category = categorize(cwes, name)
            instances = alert.get("instances") or [{}]
            for inst in instances:
                f = Finding(
                    scanner="zap",
                    scan_type=ScanType.DAST.value,
                    rule_id=f"zap-{plugin}" + (f"-{alert['alertRef']}" if alert.get("alertRef") and alert.get("alertRef") != plugin else ""),
                    title=name,
                    application=application,
                    category=category,
                    cwe=cwes,
                    severity=ZAP_RISK.get(str(alert.get("riskcode")), "info"),
                    confidence=ZAP_CONFIDENCE.get(str(alert.get("confidence"))),
                    url=inst.get("uri") or site.get("@name"),
                    http_method=(inst.get("method") or "GET").upper(),
                    parameter=inst.get("param") or None,
                    description=strip_html(alert.get("desc")),
                    remediation=strip_html(alert.get("solution")),
                    evidence="\n".join(x for x in [
                        f"attack: {inst['attack']}" if inst.get("attack") else "",
                        f"evidence: {inst['evidence']}" if inst.get("evidence") else "",
                        strip_html(inst.get("otherinfo") or ""),
                    ] if x)[:4000],
                    references=[u for u in strip_html(alert.get("reference")).split("\n") if u.strip()][:8],
                    exploitability_hint=("active attack payload succeeded" if inst.get("attack") else None),
                    detected_at=ts,
                    raw={"alert": {k: v for k, v in alert.items() if k != "instances"}, "instance": inst},
                )
                if str(alert.get("confidence")) == "0":
                    f.triage_reason = "ZAP itself marked this alert as a false positive (confidence 0)."
                if f.compute_fingerprint() in seen:  # ZAP may list the same URL+param twice
                    continue
                seen.add(f.fingerprint)
                out.append(f)
    return out


# ------------------------------------------------------------------------------- Trivy
def _trivy_cvss(v: dict[str, Any]) -> float | None:
    """CVSS v3 score consistent with the severity Trivy reports.

    Trivy's ``Severity`` comes from ``SeveritySource`` (e.g. the Debian tracker for
    OS packages, GHSA for npm). Mixing that severity with an NVD score from another
    source would produce contradictions ("low" severity scored 9.8), so only the
    matching source is used; without one the scorer falls back to severity points.
    """
    cvss = v.get("CVSS") or {}
    source = v.get("SeveritySource")
    if source:
        s = (cvss.get(source) or {}).get("V3Score")
        return float(s) if s else None
    for src in ("nvd", "ghsa", "redhat"):
        s = (cvss.get(src) or {}).get("V3Score")
        if s:
            return float(s)
    for data in cvss.values():
        if isinstance(data, dict) and data.get("V3Score"):
            return float(data["V3Score"])
    return None


def normalize_trivy(report: dict[str, Any], application: str, detected_at: str | None = None) -> list[Finding]:
    ts = detected_at or report.get("CreatedAt") or now_iso()
    artifact = report.get("ArtifactName")
    out: list[Finding] = []
    for res in report.get("Results", []) or []:
        target = res.get("Target")
        for v in res.get("Vulnerabilities", []) or []:
            vid = v.get("VulnerabilityID", "unknown")
            aliases = [vid] + [a for a in _as_list(v.get("VendorIDs")) if a != vid]
            f = Finding(
                scanner="trivy",
                scan_type=ScanType.SCA.value,
                rule_id=vid,
                title=v.get("Title") or f"{vid} in {v.get('PkgName')}",
                application=application,
                category="vulnerable-dependency",  # library flaw, not an app-code flaw
                cwe=parse_cwes(v.get("CweIDs")),
                cve=aliases,
                severity=TRIVY_SEVERITY.get(str(v.get("Severity", "UNKNOWN")).upper(), "info"),
                confidence=None,  # Trivy matches versions to advisories; it reports no confidence
                file_path=normalize_path(v.get("PkgPath") or target),
                package_name=v.get("PkgName"),
                package_version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion") or None,
                target=f"{artifact} :: {target}" if artifact else target,
                description=(v.get("Description") or "")[:3000],
                remediation=(f"Upgrade {v.get('PkgName')} to {v['FixedVersion']} or later."
                             if v.get("FixedVersion") else "No fixed version published; assess mitigation or replace the package."),
                references=([v["PrimaryURL"]] if v.get("PrimaryURL") else []) + _as_list(v.get("References"))[:5],
                cvss_score=_trivy_cvss(v),
                detected_at=ts,
                raw=v,
            )
            f.compute_fingerprint()
            out.append(f)
        for s in res.get("Secrets", []) or []:
            f = Finding(
                scanner="trivy",
                scan_type=ScanType.SCA.value,
                rule_id=f"secret:{s.get('RuleID', 'unknown')}",
                title=s.get("Title") or "Hard-coded secret",
                application=application,
                category="hardcoded-secret",
                cwe=["CWE-798"],
                severity=TRIVY_SEVERITY.get(str(s.get("Severity", "UNKNOWN")).upper(), "info"),
                file_path=normalize_path(target),
                line_start=s.get("StartLine"),
                line_end=s.get("EndLine"),
                target=f"{artifact} :: {target}" if artifact else target,
                description=f"Trivy secret rule '{s.get('RuleID')}' ({s.get('Category')}) matched.",
                remediation="Remove the secret from source control, rotate it, and load it from a secret store or environment variable.",
                evidence=mask_secret(s.get("Match")),
                detected_at=ts,
                raw={k: (mask_secret(val) if k in ("Match", "Code") and isinstance(val, str) else val)
                     for k, val in s.items() if k != "Code"},
            )
            f.compute_fingerprint()
            out.append(f)
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status") not in (None, "FAIL"):
                continue
            cause = m.get("CauseMetadata") or {}
            f = Finding(
                scanner="trivy",
                scan_type=ScanType.SCA.value,
                rule_id=f"misconfig:{m.get('AVDID') or m.get('ID')}",
                title=m.get("Title") or "Misconfiguration",
                application=application,
                category="security-misconfiguration",
                severity=TRIVY_SEVERITY.get(str(m.get("Severity", "UNKNOWN")).upper(), "info"),
                file_path=normalize_path(target),
                line_start=cause.get("StartLine"),
                line_end=cause.get("EndLine"),
                target=f"{artifact} :: {target}" if artifact else target,
                description=m.get("Description") or m.get("Message") or "",
                remediation=m.get("Resolution") or "",
                evidence=m.get("Message") or "",
                references=([m["PrimaryURL"]] if m.get("PrimaryURL") else []),
                detected_at=ts,
                raw=m,
            )
            f.compute_fingerprint()
            out.append(f)
    return out


NORMALIZERS: dict[str, Callable[[dict[str, Any], str, str | None], list[Finding]]] = {
    "semgrep": normalize_semgrep,
    "zap": normalize_zap,
    "trivy": normalize_trivy,
}


def normalize(scanner: str, report: dict[str, Any], application: str, detected_at: str | None = None) -> list[Finding]:
    try:
        fn = NORMALIZERS[scanner]
    except KeyError as exc:
        raise ValueError(f"No normalizer for scanner '{scanner}'") from exc
    return fn(report, application, detected_at)
