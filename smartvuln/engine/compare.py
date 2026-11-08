"""Comparison of two successive scans (baseline -> current).

Findings are matched by fingerprint (scanner + rule + location; see
``Finding.compute_fingerprint``). A baseline finding absent from the current
scan is classified as:

* *not re-tested* - its scanner did not complete in the current scan, so
  absence of evidence is not evidence of a fix;
* *not observed* - DAST only: the same ZAP rule still fires on other URLs of
  the site in the current scan. DAST tools sample URLs (the spider path and
  ZAP's per-alert instance list vary between runs), so a missing URL does not
  mean the weakness was fixed while the rule is still triggered elsewhere;
* *resolved* - otherwise (SAST/SCA finding gone, or the DAST rule no longer
  fires anywhere on the target).

Symmetrically, a new DAST finding whose rule already fired in the baseline is
flagged as a new *location* of a known issue (``new_known_rule``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import SEVERITY_RANK, ExecStatus, Finding, ScanType


@dataclass
class ScanComparison:
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    not_observed: list[Finding] = field(default_factory=list)
    not_retested: list[Finding] = field(default_factory=list)
    persistent: list[Finding] = field(default_factory=list)
    severity_changes: list[dict[str, Any]] = field(default_factory=list)
    coverage_changes: list[dict[str, Any]] = field(default_factory=list)
    new_known_rule: set[str] = field(default_factory=set)  # fingerprints of new DAST locations of a known rule
    moved: list[dict[str, Any]] = field(default_factory=list)  # SAST findings that only changed line

    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "new_known_rule": len(self.new_known_rule),
            "resolved": len(self.resolved),
            "not_observed": len(self.not_observed),
            "not_retested": len(self.not_retested),
            "persistent": len(self.persistent),
            "moved": len(self.moved),
            "severity_changes": len(self.severity_changes),
            "severity_increased": sum(1 for c in self.severity_changes if c["direction"] == "up"),
            "severity_decreased": sum(1 for c in self.severity_changes if c["direction"] == "down"),
            "coverage_changes": len(self.coverage_changes),
        }

    def to_dict(self) -> dict[str, Any]:
        brief = lambda fs: [{"id": f.id, "fingerprint": f.fingerprint, "scanner": f.scanner, "severity": f.severity,
                             "title": f.title, "location": f.location} for f in fs]
        new = [b | {"known_rule": b["fingerprint"] in self.new_known_rule} for b in brief(self.new)]
        return {"summary": self.summary(), "new": new, "resolved": brief(self.resolved),
                "not_observed": brief(self.not_observed),
                "not_retested": brief(self.not_retested), "persistent": brief(self.persistent), "moved": self.moved,
                "severity_changes": self.severity_changes, "coverage_changes": self.coverage_changes}


def compare_scans(baseline: list[Finding], current: list[Finding],
                  baseline_runs: dict[str, str], current_runs: dict[str, str]) -> ScanComparison:
    """``*_runs`` map scanner name -> execution status string."""
    base = {f.fingerprint: f for f in baseline}
    cur = {f.fingerprint: f for f in current}
    ok_now = {s for s, st in current_runs.items() if ExecStatus(st).produced_report}
    out = ScanComparison()
    dast = ScanType.DAST.value
    base_dast_rules = {f.rule_id for f in baseline if f.scan_type == dast}
    cur_dast_rules = {f.rule_id for f in current if f.scan_type == dast}

    for fp, f in cur.items():
        if fp not in base:
            out.new.append(f)
            if f.scan_type == dast and f.rule_id in base_dast_rules:
                out.new_known_rule.add(fp)
            continue
        out.persistent.append(f)
        old = base[fp]
        if old.severity != f.severity:
            up = SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(old.severity, 0)
            out.severity_changes.append({"fingerprint": fp, "title": f.title, "location": f.location,
                                         "from": old.severity, "to": f.severity, "direction": "up" if up else "down"})
    _pair_moved_sast(out, base, cur)
    matched_base = {m["baseline_fingerprint"] for m in out.moved}

    for fp, f in base.items():
        if fp in cur or fp in matched_base:
            continue
        if f.scanner not in ok_now:
            out.not_retested.append(f)
        elif f.scan_type == dast and f.rule_id in cur_dast_rules:
            out.not_observed.append(f)  # rule still fires elsewhere: URL sampling, not a fix
        else:
            out.resolved.append(f)

    out.new = [f for f in out.new if f.fingerprint not in {m["current_fingerprint"] for m in out.moved}]

    for scanner in sorted(set(baseline_runs) | set(current_runs)):
        b, c = baseline_runs.get(scanner, "not_run"), current_runs.get(scanner, "not_run")
        b_count = sum(1 for f in baseline if f.scanner == scanner)
        c_count = sum(1 for f in current if f.scanner == scanner)
        if b != c or b_count != c_count:
            out.coverage_changes.append({"scanner": scanner, "baseline_status": b, "current_status": c,
                                         "baseline_findings": b_count, "current_findings": c_count})
    return out


def _pair_moved_sast(out: ScanComparison, base: dict[str, Finding], cur: dict[str, Finding]) -> None:
    """Second matching pass for SAST: same scanner + rule + file, different line.

    SAST fingerprints contain the line number, so editing a file shifts every finding
    below the edit. Unmatched findings that share scanner, rule and file are paired in
    line order and treated as persistent ("moved") rather than resolved + new.
    """
    key = lambda f: (f.scanner, f.rule_id, f.file_path)
    sast = ScanType.SAST.value
    old_left: dict[tuple, list[Finding]] = {}
    new_left: dict[tuple, list[Finding]] = {}
    for fp, f in base.items():
        if fp not in cur and f.scan_type == sast and f.file_path:
            old_left.setdefault(key(f), []).append(f)
    for fp, f in cur.items():
        if fp not in base and f.scan_type == sast and f.file_path:
            new_left.setdefault(key(f), []).append(f)
    for k, olds in old_left.items():
        news = new_left.get(k, [])
        for o, n in zip(sorted(olds, key=lambda f: f.line_start or 0), sorted(news, key=lambda f: f.line_start or 0)):
            out.persistent.append(n)
            out.moved.append({"baseline_fingerprint": o.fingerprint, "current_fingerprint": n.fingerprint,
                              "title": n.title, "file": n.file_path, "from_line": o.line_start, "to_line": n.line_start})
