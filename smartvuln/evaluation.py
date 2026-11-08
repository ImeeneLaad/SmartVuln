"""Evaluation against the manually verified ground truth (evaluation/ground_truth.json).

What is measured, and what is deliberately NOT:

* Recall (TP / (TP + FN)) per scanner, over the ground-truth entries that the
  scanner can detect in principle (code location for SAST, secrets for Trivy's
  secret scanner, HTTP endpoint for DAST).
* Precision (TP / (TP + FP)) ONLY inside the closed-world scope - (file,
  category) pairs for which every occurrence was reviewed by hand. Outside it
  we cannot tell an unknown true positive from a false positive, so nothing is
  claimed. DAST precision is not computed (no closed-world DAST ground truth).
* Correlation quality: whether findings of different scanners that hit the
  same ground-truth vulnerability were grouped together, and whether any group
  wrongly merges two different ground-truth vulnerabilities.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import ExecStatus, Finding


def _code_match(f: Finding, g: dict[str, Any], tol: int) -> bool:
    if not f.file_path or f.line_start is None or f.category != g["category"]:
        return False
    return any(f.file_path == loc["file"] and abs(f.line_start - loc["line"]) <= tol for loc in g.get("code", []))


def _endpoint_match(f: Finding, g: dict[str, Any]) -> bool:
    ep = g.get("endpoint")
    if f.scan_type != "DAST" or not ep or not f.url or f.category != g["category"]:
        return False
    if ep.get("method") and f.http_method and ep["method"] != f.http_method:
        return False
    return re.search(ep["path"], urlparse(f.url).path or "/") is not None


def match(f: Finding, g: dict[str, Any], tol: int) -> bool:
    return _code_match(f, g, tol) or _endpoint_match(f, g)


def _ratio(n: int, d: int) -> float | None:
    return round(n / d, 3) if d else None


def evaluate(findings: list[Finding], gt_path: str | Path, run_statuses: dict[str, str]) -> dict[str, Any]:
    gt = json.loads(Path(gt_path).read_text(encoding="utf-8"))
    tol = int(gt.get("line_tolerance", 3))
    vulns = gt["vulnerabilities"]
    scope = gt["closed_world_scope"]["files"]
    negatives = {(n["file"], n["category"]): n for n in gt["closed_world_scope"].get("known_negatives", [])}

    matches: dict[str, list[Finding]] = defaultdict(list)  # gt id -> findings
    finding_gt: dict[str, set[str]] = defaultdict(set)     # finding id -> gt ids
    for f in findings:
        for g in vulns:
            if match(f, g, tol):
                matches[g["id"]].append(f)
                finding_gt[f.id].add(g["id"])

    # -------------------------------------------------------------- recall per detector
    detectors = {
        "semgrep (all rules)": (lambda f: f.scanner == "semgrep", lambda g: bool(g.get("code"))),
        "semgrep (SmartVuln custom rules)": (lambda f: f.scanner == "semgrep" and f.rule_id.startswith("custom."),
                                             lambda g: bool(g.get("code"))),
        "semgrep (registry rules)": (lambda f: f.scanner == "semgrep" and not f.rule_id.startswith("custom."),
                                     lambda g: bool(g.get("code"))),
        "trivy (secret scanner)": (lambda f: f.scanner == "trivy", lambda g: g["category"] == "hardcoded-secret"),
        "zap (DAST)": (lambda f: f.scanner == "zap", lambda g: bool(g.get("endpoint"))),
        "all scanners combined": (lambda f: True, lambda g: True),
    }
    recall: dict[str, Any] = {}
    for name, (fsel, gsel) in detectors.items():
        scanner = name.split(" ")[0]
        if scanner != "all":
            status = run_statuses.get(scanner, "not_run")
            if status == "not_run" or not ExecStatus(status).produced_report:
                recall[name] = {"note": f"not computed: {scanner} did not complete in this scan ({status})"}
                continue
        applicable = [g for g in vulns if gsel(g)]
        tp = [g["id"] for g in applicable if any(fsel(f) for f in matches[g["id"]])]
        fn = [g["id"] for g in applicable if g["id"] not in tp]
        recall[name] = {"applicable": len(applicable), "tp": len(tp), "fn": len(fn),
                        "recall": _ratio(len(tp), len(applicable)), "detected": tp, "missed": fn}

    # -------------------------------------------------------------- closed-world precision
    def in_scope(f: Finding) -> bool:
        code_based = f.scan_type == "SAST" or (f.scanner == "trivy" and f.category == "hardcoded-secret")
        return code_based and f.file_path in scope and f.category in scope[f.file_path]

    precision: dict[str, Any] = {}
    false_positives: list[dict[str, Any]] = []
    groups = {
        "semgrep (all rules)": lambda f: f.scanner == "semgrep",
        "semgrep (SmartVuln custom rules)": lambda f: f.scanner == "semgrep" and f.rule_id.startswith("custom."),
        "semgrep (registry rules)": lambda f: f.scanner == "semgrep" and not f.rule_id.startswith("custom."),
        "trivy (secret scanner)": lambda f: f.scanner == "trivy",
    }
    scoped = [f for f in findings if in_scope(f)]
    for f in scoped:
        if not finding_gt.get(f.id):
            neg = negatives.get((f.file_path, f.category))
            false_positives.append({"scanner": f.scanner, "rule": f.rule_id, "location": f.location,
                                    "category": f.category,
                                    "reason": neg["reason"] if neg and abs(neg["line"] - (f.line_start or 0)) <= tol
                                    else "no ground-truth vulnerability of this class at this location (closed-world scope)"})
    for name, sel in groups.items():
        sel_f = [f for f in scoped if sel(f)]
        tp = sum(1 for f in sel_f if finding_gt.get(f.id))
        precision[name] = {"in_scope_findings": len(sel_f), "tp": tp, "fp": len(sel_f) - tp,
                           "precision": _ratio(tp, len(sel_f))}
    precision["zap (DAST)"] = {"note": "not computed - no closed-world ground truth for DAST alerts"}

    # -------------------------------------------------------------- correlation quality
    correlation = []
    for g in vulns:
        fs = matches[g["id"]]
        scanners = sorted({f.scanner for f in fs})
        if len(scanners) < 2:
            continue
        group_ids = {f.group_id for f in fs}
        # scanners that share at least one group
        by_group = defaultdict(set)
        for f in fs:
            by_group[f.group_id].add(f.scanner)
        joined = max((len(s) for s in by_group.values()), default=0)
        correlation.append({"gt": g["id"], "title": g["title"], "scanners": scanners, "groups": sorted(group_ids),
                            "correlated": joined == len(scanners),
                            "partially_correlated": 1 < joined < len(scanners)})
    wrong_merges = []
    gt_by_group: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        for gid in finding_gt.get(f.id, ()):
            gt_by_group[f.group_id].add(gid)
    for grp, ids in gt_by_group.items():
        if len(ids) > 1:
            wrong_merges.append({"group": grp, "ground_truth_ids": sorted(ids)})

    return {
        "ground_truth": str(gt_path), "source_ref": gt.get("source_ref"), "entries": len(vulns),
        "line_tolerance": tol, "scanner_status": run_statuses,
        "recall": recall, "precision_closed_world": precision, "closed_world_false_positives": false_positives,
        "correlation": {"multi_scanner_ground_truth": len(correlation),
                        "fully_correlated": sum(1 for c in correlation if c["correlated"]),
                        "details": correlation, "wrong_merges": wrong_merges},
        "per_entry": [{"id": g["id"], "title": g["title"], "category": g["category"],
                       "detected_by": sorted({f.scanner + ("(custom)" if f.rule_id.startswith("custom.") else "")
                                              for f in matches[g["id"]]})} for g in vulns],
    }


def format_report(r: dict[str, Any]) -> str:
    pct = lambda x: "n/a" if x is None else f"{x * 100:.0f}%"
    out = [f"# SmartVuln evaluation - scan #{r.get('scan_id', '?')} vs ground truth {r['source_ref']} ({r['entries']} entries)", "",
           "## Recall (per detector, over the entries it can detect in principle)", "",
           "| Detector | Applicable | TP | FN | Recall |", "|---|---|---|---|---|"]
    for k, v in r["recall"].items():
        out.append(f"| {k} | " + (f"{v['applicable']} | {v['tp']} | {v['fn']} | {pct(v['recall'])} |" if "recall" in v
                                   else f"{v['note']} | | | |"))
    out += ["", "## Precision (closed-world scope only)", "", "| Detector | In-scope findings | TP | FP | Precision |",
            "|---|---|---|---|---|"]
    for k, v in r["precision_closed_world"].items():
        out.append(f"| {k} | " + (f"{v['in_scope_findings']} | {v['tp']} | {v['fp']} | {pct(v['precision'])} |"
                                   if "precision" in v else f"{v['note']} | | | |"))
    if r["closed_world_false_positives"]:
        out += ["", "False positives inside the closed-world scope:", ""]
        out += [f"- `{fp['location']}` {fp['scanner']} `{fp['rule']}` ({fp['category']}): {fp['reason']}"
                for fp in r["closed_world_false_positives"]]
    c = r["correlation"]
    out += ["", "## Correlation engine", "",
            f"Ground-truth vulnerabilities detected by 2+ scanners: {c['multi_scanner_ground_truth']}; "
            f"correctly grouped together: {c['fully_correlated']}; wrong merges of different vulnerabilities: {len(c['wrong_merges'])}", ""]
    out += [f"- {d['gt']} {d['title']}: {', '.join(d['scanners'])} -> {'grouped' if d['correlated'] else 'NOT grouped'} {d['groups']}"
            for d in c["details"]]
    out += ["", "## Per entry", "", "| GT | Vulnerability | Class | Detected by |", "|---|---|---|---|"]
    out += [f"| {e['id']} | {e['title']} | {e['category']} | {', '.join(e['detected_by']) or '**missed**'} |" for e in r["per_entry"]]
    return "\n".join(out) + "\n"
