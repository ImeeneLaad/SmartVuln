"""Self-contained HTML reports and the Markdown pipeline summary."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import SEVERITIES, Finding

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)


def _ctx(scan: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    primary = [f for f in findings if f.is_group_primary]
    return {
        "scan": scan, "findings": findings, "primary": primary,
        "severities": SEVERITIES,
        "sev_counts": Counter(f.severity for f in primary),
        "sev_counts_all": Counter(f.severity for f in findings),
        "prio_counts": Counter(f.priority for f in primary),
        "type_counts": Counter(f.scan_type for f in findings),
        "scanner_counts": Counter(f.scanner for f in findings),
        "multi": [f for f in primary if f.correlation_status == "multi_scanner"],
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def render_html_report(scan: dict[str, Any], findings: list[Finding], comparison: dict[str, int] | None) -> str:
    return _env.get_template("report.html").render(**_ctx(scan, findings), comparison=comparison)


def render_comparison_html(baseline: dict[str, Any], current: dict[str, Any], cmp) -> str:
    return _env.get_template("comparison.html").render(
        baseline=baseline, current=current, cmp=cmp, summary=cmp.summary(),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))


def render_markdown_summary(scan: dict[str, Any], findings: list[Finding], comparison: dict[str, int] | None) -> str:
    c = _ctx(scan, findings)
    lines = [f"## SmartVuln scan #{scan['id']} - {scan['application']}" + (" (DEMO FIXTURES)" if scan["is_demo"] else ""),
             "", f"Status: **{scan['status']}** | source `{scan.get('source_ref') or '-'}` | target `{scan.get('target_url')}`",
             "", "| Scanner | Type | Status | Duration | Findings |", "|---|---|---|---|---|"]
    for r in scan["runs"]:
        lines.append(f"| {r['scanner']} | {r['scan_type']} | {r['status']} | {r['duration_s'] or 0:.0f}s | {r['findings_count']} |")
    lines += ["", f"**{len(findings)} findings -> {len(c['primary'])} unique issues** after deduplication/correlation "
              f"({len(c['multi'])} confirmed by more than one scanner).", "",
              "| " + " | ".join(s.capitalize() for s in SEVERITIES) + " |", "|" + "---|" * len(SEVERITIES),
              "| " + " | ".join(str(c["sev_counts"].get(s, 0)) for s in SEVERITIES) + " |", "",
              "Priority (unique issues): " + ", ".join(f"{p}: {c['prio_counts'].get(p, 0)}" for p in ("P1", "P2", "P3", "P4"))]
    if comparison:
        lines += ["", "Compared with the previous scan: " + ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in comparison.items())]
    top = c["primary"][:10]
    if top:
        lines += ["", "### Top 10 by risk score", "", "| Score | Prio | Severity | Scanner(s) | Title | Location |", "|---|---|---|---|---|---|"]
        by_id = {f.id: f for f in findings}
        for f in top:
            scanners = sorted({f.scanner} | {by_id[i].scanner for i in f.related_ids if i in by_id})
            lines.append(f"| {f.risk_score:.0f} | {f.priority} | {f.severity} | {', '.join(scanners)} | "
                         f"{f.title[:70].replace('|', '/')} | `{f.location[:70]}` |")
    lines += ["", "_All findings need manual verification; SmartVuln never auto-confirms a vulnerability._"]
    return "\n".join(lines) + "\n"
