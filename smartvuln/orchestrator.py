"""End-to-end workflow: run scanners -> analyze -> persist -> report."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import cfg_for_target, resolve
from .database.store import Store
from .engine.compare import compare_scans
from .engine.normalize import mask_secret
from .engine.pipeline import AnalysisResult, analyze
from .models import ExecStatus, ScannerRun
from .sourcehash import source_hash
from .reports.render import render_comparison_html, render_html_report, render_markdown_summary
from .scanners.semgrep import SemgrepAdapter
from .scanners.trivy import TrivyAdapter
from .scanners.zap import ZapAdapter

log = logging.getLogger(__name__)
ADAPTERS = {"semgrep": SemgrepAdapter, "trivy": TrivyAdapter, "zap": ZapAdapter}
REPORT_FILES = {"semgrep": ["semgrep.json"], "trivy": ["trivy-image.json", "trivy-fs.json"], "zap": ["zap-report.json"]}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def store_for(cfg: dict[str, Any]) -> Store:
    return Store(resolve(cfg["general"]["database"]))


def _source_ref(src: Path) -> str:
    """git describe for a checkout, otherwise a content hash ("src:<12 hex>") of the folder."""
    if (src / ".git").exists() and shutil.which("git"):
        r = subprocess.run(["git", "-C", str(src), "describe", "--tags", "--always", "--dirty"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    h = source_hash(src)
    return f"src:{h}" if h else ""


def _fresh_scan_dir(cfg: dict[str, Any], scan_id: int) -> Path:
    """Folder for a NEW scan. Scan numbers can be reused after deletions, so a leftover folder
    with the same number (e.g. from a scan removed outside SmartVuln) is moved aside to
    data/scans/_replaced/ - never deleted, never mixed with the new scan's files."""
    scans_root = resolve(cfg["general"]["data_dir"]) / "scans"
    scan_dir = scans_root / f"{scan_id:04d}"
    if scan_dir.exists():
        target = scans_root / "_replaced" / f"{scan_id:04d}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(scan_dir), str(target))
        log.warning("leftover folder for scan number %s moved to %s", scan_id, target)
    return scan_dir


class ScanLog:
    """Execution log of one scan: SQLite rows (shown live in the dashboard) + one file per source.

    The database keeps at most ``max_db_lines`` lines per source so a chatty tool cannot
    bloat it; the per-source log file under ``<scan_dir>/logs/`` always has everything.
    """

    def __init__(self, store: Store, scan_id: int, log_dir: Path, max_db_lines: int = 1500):
        self.store, self.scan_id, self.log_dir = store, scan_id, log_dir
        self.max_db_lines = max_db_lines
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()
        log_dir.mkdir(parents=True, exist_ok=True)

    def __call__(self, source: str, message: str) -> None:
        message = mask_secret(message.rstrip())
        if not message:
            return
        with self._lock:
            with open(self.log_dir / f"{source}.log", "a", encoding="utf-8") as fh:
                fh.write(f"{_now()} {message}\n")
            n = self._counts.get(source, 0) + 1
            self._counts[source] = n
        if n <= self.max_db_lines:
            self.store.add_log(self.scan_id, source, message)
        elif n == self.max_db_lines + 1:
            self.store.add_log(self.scan_id, source, f"... further {source} output only in logs/{source}.log")


def run_scan(cfg: dict[str, Any], scanners: list[str], label: str = "", allow_external: bool = False,
             scan_id: int | None = None) -> int:
    """Execute the selected scanners, then analyze, persist and report.

    ``scan_id`` lets the web dashboard create the scan record first (to return its id
    immediately) and run this function in a background thread.
    """
    store = store_for(cfg)
    app = cfg["general"]["application"]
    src = resolve(cfg["source"]["path"])
    started = _now()
    if scan_id is None:
        scan_id = store.create_scan(app, cfg["target"]["url"], _source_ref(src), label, started_at=started,
                                    scanners=scanners)
    else:
        started = store.get_scan(scan_id)["started_at"]
    scan_dir = _fresh_scan_dir(cfg, scan_id)
    raw_dir = scan_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    try:  # scanner containers run as non-root users (zap uid 1000, semgrep): output dir must be writable
        os.chmod(raw_dir, 0o777)
    except OSError:
        pass
    slog = ScanLog(store, scan_id, scan_dir / "logs")
    store.set_phase(scan_id, "running scanners", 0.02, str(scan_dir))
    if not store.scanner_runs(scan_id):
        store.add_pending_runs(scan_id, [(s, ADAPTERS[s].scan_type) for s in scanners])
    slog("smartvuln", f"scan #{scan_id} started: scanners {', '.join(scanners)}; output {scan_dir}")
    log.info("scan #%s -> %s", scan_id, scan_dir)

    done = {"n": 0}
    lock = threading.Lock()

    def _run(name: str) -> ScannerRun:
        adapter = ADAPTERS[name](cfg.get(name, {}), cfg, raw_dir, on_log=lambda m: slog(name, m))
        if isinstance(adapter, ZapAdapter):
            adapter.allow_external = allow_external
        store.mark_run_started(scan_id, name)
        slog("smartvuln", f"{name} ({adapter.scan_type}) started")
        try:
            run = adapter.run()
        except Exception as exc:  # an adapter bug must not lose the other scanners' results
            log.exception("%s adapter crashed", name)
            run = ScannerRun(scanner=name, scan_type=adapter.scan_type, status=ExecStatus.FAILED.value,
                             error=f"adapter error: {exc}")
        store.add_scanner_run(scan_id, run)  # final status visible immediately, before analysis
        slog("smartvuln", f"{name} finished: {run.status} in {run.duration_s:.0f}s"
                          + (f" - {run.error}" if run.error else ""))
        with lock:
            done["n"] += 1
            store.set_phase(scan_id, "running scanners", 0.05 + 0.8 * done["n"] / len(scanners))
        return run

    static = [s for s in scanners if s in ("semgrep", "trivy")]
    runs: list[ScannerRun] = []
    if static:
        with ThreadPoolExecutor(max_workers=len(static)) as pool:
            runs.extend(pool.map(_run, static))
    if "zap" in scanners:  # DAST last: the static scans do not depend on the running target
        runs.append(_run("zap"))

    return _finalize(cfg, store, scan_id, scan_dir, runs, started, slog)


def import_reports(cfg: dict[str, Any], raw_dir: str | Path, label: str = "", is_demo: bool = False) -> int:
    """Analyze already-produced raw reports (e.g. downloaded CI artifacts or demo fixtures)."""
    raw_src = Path(raw_dir)
    store = store_for(cfg)
    started = _now()
    scan_id = store.create_scan(cfg["general"]["application"], cfg["target"]["url"],
                                _source_ref(resolve(cfg["source"]["path"])), label, is_demo=is_demo, started_at=started)
    scan_dir = _fresh_scan_dir(cfg, scan_id)
    (scan_dir / "raw").mkdir(parents=True, exist_ok=True)
    runs: list[ScannerRun] = []
    for scanner in REPORT_FILES:
        # accept the adapter's own names and variants such as semgrep_sample.json / zap-report.json
        found = sorted(p for p in raw_src.glob(f"*{scanner}*.json") if p.is_file() and "plan" not in p.name)
        if not found:
            runs.append(ScannerRun(scanner=scanner, scan_type=ADAPTERS[scanner].scan_type,
                                   status=ExecStatus.SKIPPED.value, error="no report in imported folder"))
            continue
        for p in found:
            shutil.copy2(p, scan_dir / "raw" / p.name)
        runs.append(ScannerRun(scanner=scanner, scan_type=ADAPTERS[scanner].scan_type, status=ExecStatus.SUCCESS.value,
                               raw_report_paths=[str(scan_dir / "raw" / p.name) for p in found],
                               error="imported report (scanner not executed by SmartVuln)"))
    return _finalize(cfg, store, scan_id, scan_dir, runs, started)


def _finalize(cfg: dict[str, Any], store: Store, scan_id: int, scan_dir: Path,
              runs: list[ScannerRun], started: str, slog: ScanLog | None = None) -> int:
    say = slog or (lambda source, msg: log.info(msg))
    store.set_phase(scan_id, "analysis: normalize, correlate, score", 0.88)
    raw = {r.scanner: r.raw_report_paths for r in runs if r.raw_report_paths}
    say("smartvuln", "analysis started on raw reports: " +
        (", ".join(Path(p).name for ps in raw.values() for p in ps) or "none"))
    result: AnalysisResult = analyze(
        raw, cfg["general"]["application"], source_root=resolve(cfg["source"]["path"]),
        entrypoint=cfg["source"].get("entrypoint", "server.ts"), scoring_cfg=cfg.get("scoring"),
        line_tolerance=int(cfg.get("correlation", {}).get("line_tolerance", 2)),
        decisions=store.triage_decisions(), detected_at=started)
    for err in result.parse_errors:
        say("smartvuln", f"parse error: {err}")
    for r in runs:
        r.findings_count = sum(1 for f in result.findings if f.scanner == r.scanner)
        store.add_scanner_run(scan_id, r)
    store.save_findings(scan_id, result.findings)
    stats = result.stats()
    stats["parse_errors"] = result.parse_errors
    c = stats["correlation"]
    say("smartvuln", f"analysis done: {stats['total']} findings -> {stats['unique_issues']} unique issues, "
                     f"{c.get('multi_scanner_groups', 0)} multi-scanner groups ({c.get('sast_dast_groups', 0)} SAST+DAST), "
                     f"{result.routes_mapped} routes mapped")

    produced = [r for r in runs if ExecStatus(r.status).produced_report]
    status = "completed" if len(produced) == len(runs) else ("partial" if produced else "failed")
    store.set_phase(scan_id, "writing reports", 0.95)
    store.save_stats(scan_id, stats)
    paths = write_reports(cfg, store, scan_id, scan_dir, final_status=status)
    say("smartvuln", "reports written: " + ", ".join(p.name for p in paths.values()))
    store.finish_scan(scan_id, status, stats, str(scan_dir))
    say("smartvuln", f"scan #{scan_id} {status}")
    log.info("scan #%s %s: %s findings (%s unique issues)", scan_id, status, stats["total"], stats["unique_issues"])
    return scan_id


COMPARISON_FILES = ("comparison.json", "comparison-report.html")


def delete_scan(cfg: dict[str, Any], scan_id: int) -> dict[str, Any]:
    """Delete one scan and everything that belongs only to it.

    Removed: the scan row and, through ON DELETE CASCADE, its scanner runs, findings and
    log lines; its own report folder data/scans/NNNN (only if it is exactly that folder).
    Kept: every other scan, and analyst verdicts (they are stored per finding fingerprint
    and shared by all scans of the same code/endpoint).
    The next scan of the same target that was compared against this one gets its
    comparison report regenerated against its new predecessor (or removed if none).
    """
    store = store_for(cfg)
    scan = store.get_scan(scan_id)
    if not scan:
        raise LookupError(f"scan #{scan_id} does not exist")
    if scan["status"] == "running":
        raise RuntimeError(f"scan #{scan_id} is still running; wait until it finishes")

    # A later scan whose comparison baseline is the scan being deleted.
    dependent = None
    for s in reversed(store.list_scans(1000, finished_only=True)):  # oldest first
        if s["id"] > scan_id and s["application"] == scan["application"]:
            if store.previous_scan_id(s["id"]) == scan_id:
                dependent = s
            break

    findings_count = len(store.findings(scan_id))
    store.delete_scan(scan_id)

    folder_removed = False
    expected = (resolve(cfg["general"]["data_dir"]) / "scans" / f"{scan_id:04d}").resolve()
    if scan.get("scan_dir"):
        folder = Path(scan["scan_dir"]).resolve()
        if folder == expected and folder.is_dir():  # never remove anything but this scan's own folder
            shutil.rmtree(folder)
            folder_removed = True

    updated = []
    if dependent and dependent.get("scan_dir"):
        dep_dir = Path(dependent["scan_dir"])
        for name in COMPARISON_FILES:
            (dep_dir / name).unlink(missing_ok=True)
        write_reports(cfg_for_target(cfg, dependent["application"]), store, dependent["id"], dep_dir)
        updated.append(dependent["id"])

    log.info("scan #%s deleted (%s findings, folder removed: %s, reports updated: %s)",
             scan_id, findings_count, folder_removed, updated)
    return {"deleted": scan_id, "label": scan["label"], "application": scan["application"],
            "findings_removed": findings_count, "folder_removed": folder_removed, "reports_updated": updated}


def reanalyze(cfg: dict[str, Any], scan_id: int) -> dict[str, Any]:
    """Re-run the analysis engine on a finished scan's preserved raw reports (no scanner runs).

    Used after an engine upgrade so that stored scans use the current normalization,
    fingerprints, correlation and scoring. Scan times and scanner execution data are kept.
    """
    store = store_for(cfg)
    scan = store.get_scan(scan_id)
    if not scan or scan["status"] not in ("completed", "partial"):
        raise ValueError(f"scan #{scan_id} is not a finished scan")
    cfg = cfg_for_target(cfg, scan["application"])
    raw = {r["scanner"]: [p for p in r["raw_reports"] if Path(p).is_file()] for r in scan["runs"]}
    raw = {k: v for k, v in raw.items() if v}
    result = analyze(raw, scan["application"], source_root=resolve(cfg["source"]["path"]),
                     entrypoint=cfg["source"].get("entrypoint", "server.ts"), scoring_cfg=cfg.get("scoring"),
                     line_tolerance=int(cfg.get("correlation", {}).get("line_tolerance", 2)),
                     decisions=store.triage_decisions(), detected_at=scan["started_at"])
    store.replace_findings(scan_id, result.findings)
    for r in scan["runs"]:
        store.set_findings_count(scan_id, r["scanner"], sum(1 for f in result.findings if f.scanner == r["scanner"]))
    stats = result.stats()
    stats["parse_errors"] = result.parse_errors
    store.save_stats(scan_id, stats)
    write_reports(cfg, store, scan_id, Path(scan["scan_dir"]))
    store.add_log(scan_id, "smartvuln", f"re-analysed with the current engine: {stats['total']} findings, "
                                        f"{stats['unique_issues']} unique issues")
    return stats


def comparison_for(store: Store, scan_id: int, baseline_id: int | None = None):
    baseline_id = baseline_id or store.previous_scan_id(scan_id)
    if not baseline_id:
        return None, None
    cmp = compare_scans(store.findings(baseline_id), store.findings(scan_id),
                        store.run_statuses(baseline_id), store.run_statuses(scan_id))
    return baseline_id, cmp


def write_reports(cfg: dict[str, Any], store: Store, scan_id: int, scan_dir: Path,
                  final_status: str | None = None) -> dict[str, Path]:
    scan = store.get_scan(scan_id)
    if final_status:  # reports are written just before the scan record is marked finished
        scan["status"] = final_status
    findings = store.findings(scan_id)
    out: dict[str, Path] = {}
    norm = scan_dir / "normalized-findings.json"
    norm.write_text(json.dumps({"scan": _scan_meta(scan), "findings": [f.to_dict() for f in findings]},
                               indent=2, default=str), encoding="utf-8")
    out["normalized"] = norm
    baseline_id, cmp = comparison_for(store, scan_id)
    if cmp:
        p = scan_dir / "comparison.json"
        p.write_text(json.dumps({"baseline_scan": baseline_id, "current_scan": scan_id, **cmp.to_dict()}, indent=2),
                     encoding="utf-8")
        out["comparison"] = p
        h = scan_dir / "comparison-report.html"
        h.write_text(render_comparison_html(store.get_scan(baseline_id), scan, cmp), encoding="utf-8")
        out["comparison_html"] = h
    html = scan_dir / "report.html"
    html.write_text(render_html_report(scan, findings, cmp.summary() if cmp else None), encoding="utf-8")
    out["html"] = html
    md = scan_dir / "summary.md"
    md.write_text(render_markdown_summary(scan, findings, cmp.summary() if cmp else None), encoding="utf-8")
    out["summary"] = md
    return out


def _scan_meta(scan: dict[str, Any]) -> dict[str, Any]:
    return {k: scan[k] for k in ("id", "started_at", "finished_at", "application", "target_url", "source_ref",
                                 "label", "is_demo", "status", "stats")} | {
        "scanner_runs": [{k: r[k] for k in ("scanner", "scan_type", "status", "exit_code", "duration_s",
                                            "tool_version", "error", "findings_count")} for r in scan["runs"]]}
