"""SmartVuln Flask dashboard."""

from __future__ import annotations

import json
import os
import secrets
from collections import Counter
from pathlib import Path
from typing import Any

from datetime import datetime

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for

from ..config import cfg_for_target, load_config, resolve
from ..database.store import ScanConflict, Store
from ..engine.compare import compare_scans
from ..engine.triage import TriageDecision
from ..models import SEVERITIES, SEVERITY_RANK, Finding
from ..reports.render import render_comparison_html, render_html_report
from ..orchestrator import delete_scan
from ..scan_manager import SCANNER_INFO, STATUS_LABELS, ScanManager

FILTER_FIELDS = ("q", "severity", "scanner", "scan_type", "category", "correlation", "triage", "priority", "ident")
FINISHED = ("completed", "partial")
# Files the orchestrator writes into a scan folder; only these are served by /reports/<id>/<name>.
REPORT_FILES = {
    "report.html": ("HTML assessment report", "text/html"),
    "normalized-findings.json": ("Normalized findings (JSON)", "application/json"),
    "comparison-report.html": ("Comparison report vs previous scan (HTML)", "text/html"),
    "comparison.json": ("Comparison vs previous scan (JSON)", "application/json"),
    "summary.md": ("Pipeline summary (Markdown)", "text/markdown; charset=utf-8"),
}


def _duration(scan_or_run: dict[str, Any]) -> float | None:
    start, end = scan_or_run.get("started_at"), scan_or_run.get("finished_at")
    if not start:
        return None
    try:
        t0 = datetime.fromisoformat(start)
        t1 = datetime.fromisoformat(end) if end else datetime.now(t0.tzinfo)
        return max(0.0, (t1 - t0).total_seconds())
    except ValueError:
        return None


def create_app(cfg: dict[str, Any] | None = None) -> Flask:
    cfg = cfg or load_config()
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SMARTVULN_SECRET_KEY") or secrets.token_hex(32)
    store = Store(resolve(cfg["general"]["database"]))
    interrupted = store.mark_interrupted()  # threads of a previous server process are gone
    if interrupted:
        app.logger.warning("%s scan(s) left running by a previous process marked as interrupted", interrupted)
    manager = ScanManager(cfg, store)
    app.extensions["smartvuln_store"] = store
    app.extensions["smartvuln_manager"] = manager

    # ------------------------------------------------------------------ helpers
    def current_scan_id() -> int | None:
        sid = request.args.get("scan", type=int)
        return sid or store.latest_scan_id()

    def load(scan_id: int | None, finished: bool = True) -> tuple[dict[str, Any] | None, list[Finding]]:
        """Load a scan and its findings; with ``finished`` only completed/partial scans are served."""
        if not scan_id:
            return None, []
        scan = store.get_scan(scan_id)
        if not scan or (finished and scan["status"] not in FINISHED):
            abort(404)
        return scan, store.findings(scan_id)

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    def scan_json(scan: dict[str, Any]) -> dict[str, Any]:
        runs = []
        for r in scan["runs"]:
            runs.append({"scanner": r["scanner"], "label": SCANNER_INFO.get(r["scanner"], {}).get("label", r["scanner"]),
                         "scan_type": r["scan_type"], "status": r["status"],
                         "status_label": STATUS_LABELS.get(r["status"], r["status"]),
                         "started_at": r.get("started_at"), "finished_at": r.get("finished_at"),
                         "duration_s": r["duration_s"] if r["status"] not in ("pending", "running") else _duration(r),
                         "exit_code": r["exit_code"], "tool_version": r["tool_version"], "error": r["error"],
                         "findings_count": r["findings_count"],
                         "raw_reports": [Path(p).name for p in r["raw_reports"]]})
        st = scan.get("stats") or {}
        return {"id": scan["id"], "status": scan["status"], "phase": scan.get("phase"),
                "progress": scan.get("progress") or 0, "label": scan["label"], "application": scan["application"],
                "target_url": scan["target_url"], "source_ref": scan["source_ref"],
                "started_at": scan["started_at"], "finished_at": scan["finished_at"], "duration_s": _duration(scan),
                "error": scan.get("error"), "runs": runs, "log_lines": store.log_count(scan["id"]),
                "stats": {k: st.get(k) for k in ("total", "unique_issues", "unique_by_severity", "by_scanner")},
                "reports": [n for n in REPORT_FILES if scan.get("scan_dir") and (Path(scan["scan_dir"]) / n).is_file()]
                if scan["status"] in FINISHED else []}

    def target_names() -> dict[str, str]:
        return {t["id"]: t["name"] for t in manager.targets()}

    @app.context_processor
    def inject() -> dict[str, Any]:
        return {"severities": SEVERITIES, "csrf_token": csrf_token, "all_scans": store.list_scans(50, finished_only=True),
                "running_scan": store.running_scan(), "status_labels": STATUS_LABELS, "duration": _duration,
                "target_names": target_names()}

    @app.template_filter("pretty_json")
    def pretty_json(value: Any) -> str:
        return json.dumps(value, indent=2, default=str)

    @app.template_filter("dur")
    def fmt_duration(seconds: float | None) -> str:
        if seconds is None:
            return "-"
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s:02d}s" if m else f"{s}s"

    # ------------------------------------------------------------------ overview
    @app.route("/")
    def overview():
        scan, findings = load(current_scan_id())
        if not scan:
            return render_template("empty.html", scan=None)
        primary = [f for f in findings if f.is_group_primary]
        by_id = {f.id: f for f in findings}
        charts = {
            "severity": [sum(1 for f in primary if f.severity == s) for s in SEVERITIES],
            "severity_all": [sum(1 for f in findings if f.severity == s) for s in SEVERITIES],
            "scanner": dict(Counter(f.scanner for f in findings)),
            "scan_type": dict(Counter(f.scan_type for f in findings)),
            "priority": [sum(1 for f in primary if f.priority == p) for p in ("P1", "P2", "P3", "P4")],
            "correlation": dict(Counter(f.correlation_status for f in findings)),
            "category": dict(Counter(f.category for f in primary).most_common(10)),
            "risk_hist": _histogram([f.risk_score for f in primary]),
            "scanner_sev": {sc: dict(Counter(f.severity for f in findings if f.scanner == sc))
                            for sc in sorted({f.scanner for f in findings})},
        }
        multi = [f for f in primary if f.correlation_status == "multi_scanner"]
        return render_template("overview.html", scan=scan, findings=findings, primary=primary, charts=charts,
                               top=primary[:10], multi=multi, by_id=by_id, target_name=target_names().get(
                                   scan["application"], scan["application"]),
                               sast_dast=[f for f in multi if {"SAST", "DAST"} <= _group_types(f, by_id)])

    # ------------------------------------------------------------------ findings explorer
    @app.route("/findings")
    def findings_view():
        scan, findings = load(current_scan_id())
        if not scan:
            return render_template("empty.html")
        flt = {k: request.args.get(k, "").strip() for k in FILTER_FIELDS}
        primary_only = request.args.get("primary") == "1"
        sel = [f for f in findings if _match(f, flt) and (f.is_group_primary or not primary_only)]
        sort = request.args.get("sort", "risk")
        keyfn = {"risk": lambda f: -f.risk_score, "severity": lambda f: -SEVERITY_RANK.get(f.severity, 0),
                 "scanner": lambda f: f.scanner, "location": lambda f: f.location}.get(sort, lambda f: -f.risk_score)
        sel.sort(key=keyfn)
        options = {
            "scanner": sorted({f.scanner for f in findings}),
            "scan_type": sorted({f.scan_type for f in findings}),
            "category": sorted({f.category for f in findings}),
            "correlation": sorted({f.correlation_status for f in findings}),
            "triage": sorted({f.triage_status for f in findings}),
        }
        return render_template("findings.html", scan=scan, findings=sel, total=len(findings), flt=flt,
                               primary_only=primary_only, options=options, sort=sort,
                               by_id={f.id: f for f in findings})

    @app.route("/findings/<finding_id>")
    def finding_detail(finding_id: str):
        scan, findings = load(current_scan_id())
        if not scan:
            abort(404)
        by_id = {f.id: f for f in findings}
        f = by_id.get(finding_id) or abort(404)
        related = [by_id[i] for i in f.related_ids if i in by_id]
        return render_template("finding.html", scan=scan, f=f, related=related,
                               history=store.finding_history(f.fingerprint), log=store.triage_log(f.fingerprint),
                               snippet=_source_snippet(cfg_for_target(cfg, scan["application"]), f))

    @app.post("/findings/<finding_id>/triage")
    def triage(finding_id: str):
        if request.form.get("csrf") != session.get("csrf"):
            abort(400, "invalid CSRF token")
        scan_id = request.form.get("scan", type=int)
        f = store.finding(scan_id, finding_id) or abort(404)
        try:
            store.set_triage(TriageDecision(f.fingerprint, request.form.get("status", ""),
                                            request.form.get("note", ""), request.form.get("analyst", "")))
            flash("Verdict recorded. It applies to this finding in every scan with the same fingerprint.", "ok")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("finding_detail", finding_id=finding_id, scan=scan_id))

    # ------------------------------------------------------------------ history & comparison
    @app.route("/scans")
    def scans():
        every = store.list_scans(100)  # every scan that was started, including running/failed ones
        finished = list(reversed([s for s in every if s["status"] in FINISHED]))
        trend = {"labels": [f"#{s['id']}" for s in finished],
                 "series": {sev: [s["stats"].get("unique_by_severity", {}).get(sev, 0) for s in finished]
                            for sev in SEVERITIES}}
        prev_finished: dict[int, int] = {}  # scan id -> previous finished scan of the SAME target
        last: dict[str, int] = {}
        for s in reversed(every):
            if s["status"] in FINISHED:
                if s["application"] in last:
                    prev_finished[s["id"]] = last[s["application"]]
                last[s["application"]] = s["id"]
        return render_template("scans.html", scans=every, trend=trend, finished_count=len(finished),
                               prev_finished=prev_finished)

    @app.route("/compare")
    def compare():
        finished = store.list_scans(100, finished_only=True)
        ids = {s["id"] for s in finished}
        current = request.args.get("current", type=int) or (finished[0]["id"] if finished else None)
        baseline = request.args.get("baseline", type=int) or (store.previous_scan_id(current) if current else None)
        if not current or not baseline or current not in ids or baseline not in ids:
            error = None
            if request.args.get("current") or request.args.get("baseline"):
                error = "Both scans must exist and be completed."
            elif len(finished) < 2:
                error = None
            return render_template("compare.html", cmp=None, baseline=None, current=None, finished=finished,
                                   error=error)
        if baseline == current:
            return render_template("compare.html", cmp=None, baseline=None, current=None, finished=finished,
                                   error="Choose two different scans.")
        b_scan, c_scan = store.get_scan(baseline), store.get_scan(current)
        if b_scan["application"] != c_scan["application"]:
            return render_template("compare.html", cmp=None, baseline=None, current=None, finished=finished,
                                   error=f"Scan #{baseline} and #{current} are of different targets "
                                         f"({b_scan['application']} vs {c_scan['application']}).")
        b_f, c_f = store.findings(baseline), store.findings(current)
        cmp = compare_scans(b_f, c_f, store.run_statuses(baseline), store.run_statuses(current))
        scanners = sorted({f.scanner for f in b_f + c_f})
        viz = {
            "severity": {"before": [sum(1 for f in b_f if f.severity == s) for s in SEVERITIES],
                         "after": [sum(1 for f in c_f if f.severity == s) for s in SEVERITIES]},
            "scanner": {"labels": scanners,
                        "before": [sum(1 for f in b_f if f.scanner == s) for s in scanners],
                        "after": [sum(1 for f in c_f if f.scanner == s) for s in scanners]},
            "resolved_by_sev": [sum(1 for f in cmp.resolved if f.severity == s) for s in SEVERITIES],
        }
        remaining = sorted(cmp.persistent + cmp.not_observed, key=lambda f: -f.risk_score)
        return render_template("compare.html", cmp=cmp, summary=cmp.summary(), finished=finished, viz=viz,
                               remaining=remaining, before_total=len(b_f), after_total=len(c_f),
                               baseline=b_scan, current=c_scan, error=None)

    # ------------------------------------------------------------------ reports
    @app.route("/reports")
    def reports():
        items = []
        for s in store.list_scans(100, finished_only=True):
            folder = Path(s["scan_dir"] or "")
            files = [(n, REPORT_FILES[n][0], (folder / n).stat().st_size) for n in REPORT_FILES if (folder / n).is_file()]
            raws = [(Path(p).name, r["scanner"]) for r in s["runs"] for p in r["raw_reports"] if Path(p).is_file()]
            if files or raws:
                items.append({"scan": s, "files": files, "raws": raws})
        return render_template("reports.html", items=items, scan=None)

    @app.route("/reports/<int:scan_id>/<name>")
    def report_file(scan_id: int, name: str):
        """Serve a report file the orchestrator actually wrote (whitelisted names only)."""
        scan = store.get_scan(scan_id)
        if not scan or scan["status"] not in FINISHED or name not in REPORT_FILES:
            abort(404)
        path = Path(scan["scan_dir"]) / name
        if not path.is_file():
            abort(404)
        mime = REPORT_FILES[name][1]
        headers = {} if mime.startswith("text/html") else {"Content-Disposition": f"inline; filename=scan-{scan_id}-{name}"}
        return Response(path.read_text(encoding="utf-8"), mimetype=mime.split(";")[0], headers=headers)

    # ------------------------------------------------------------------ scan center
    @app.route("/scan")
    def scan_center():
        # Follow the scan named in the URL, else the one currently running; a finished scan of
        # possibly another target is not shown by default (its results live on the Overview).
        focus = request.args.get("scan", type=int)
        running = store.running_scan()
        if not focus and running:
            focus = running["id"]
        focused = store.get_scan(focus) if focus else None
        selected = request.args.get("target") or (focused["application"] if focused else None)
        targets = manager.targets()
        return render_template("scan_center.html", targets=targets, scanner_info=SCANNER_INFO,
                               focus=focus, scan=None, selected_target=selected,
                               next_numbers={t["id"]: manager.next_number(t["id"]) for t in targets})

    @app.route("/logs")
    def logs_page():
        every = store.list_scans(100)
        sid = request.args.get("scan", type=int) or (every[0]["id"] if every else None)
        scan = store.get_scan(sid) if sid else None
        if sid and not scan:
            abort(404)
        source = request.args.get("source") or None
        lines = store.logs(sid, 0, 5000, source) if scan else []
        files = []
        if scan and scan.get("scan_dir"):
            log_dir = Path(scan["scan_dir"]) / "logs"
            files = sorted(p.name for p in log_dir.glob("*.log")) if log_dir.is_dir() else []
        return render_template("logs.html", log_scan=scan, scans=every, lines=lines, source=source, files=files,
                               scan=None)

    @app.route("/logs/<int:scan_id>/<name>")
    def log_file(scan_id: int, name: str):
        scan = store.get_scan(scan_id)
        if not scan or not scan.get("scan_dir"):
            abort(404)
        log_dir = Path(scan["scan_dir"]) / "logs"
        allowed = {p.name: p for p in log_dir.glob("*.log")} if log_dir.is_dir() else {}
        if name not in allowed:  # only files that exist in this scan's log folder
            abort(404)
        return Response(allowed[name].read_text(encoding="utf-8", errors="replace"), mimetype="text/plain")

    # ------------------------------------------------------------------ JSON API
    def _check_csrf() -> None:
        token = request.headers.get("X-CSRF-Token") or (request.get_json(silent=True) or {}).get("csrf")
        if not token or token != session.get("csrf"):
            abort(400, "invalid CSRF token")

    @app.get("/api/targets")
    def api_targets():
        try:
            return jsonify(manager.preflight(request.args.get("target") or None))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/scans")
    def api_start_scan():
        _check_csrf()
        body = request.get_json(silent=True) or {}
        scanners = body.get("scanners") or []
        if not isinstance(scanners, list) or not all(isinstance(s, str) for s in scanners):
            return jsonify({"error": "scanners must be a list of names"}), 400
        unknown = sorted(set(scanners) - set(SCANNER_INFO))
        if unknown:
            return jsonify({"error": f"unknown scanner(s): {', '.join(unknown)}"}), 400
        try:
            scan_id = manager.start(str(body.get("target", "")), scanners, str(body.get("label", ""))[:120])
        except ScanConflict as exc:
            return jsonify({"error": str(exc), "running_scan": (store.running_scan() or {}).get("id")}), 409
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"scan_id": scan_id, "status_url": url_for("api_scan", scan_id=scan_id)}), 202

    @app.get("/api/scans")
    def api_scans():
        return jsonify([scan_json(s) for s in store.list_scans(100)])

    @app.get("/api/scans/<int:scan_id>")
    def api_scan(scan_id: int):
        scan = store.get_scan(scan_id) or abort(404)
        return jsonify(scan_json(scan))

    @app.delete("/api/scans/<int:scan_id>")
    def api_delete_scan(scan_id: int):
        """Delete a scan. The body must repeat the scan number ({"confirm": <id>}) as a guard."""
        _check_csrf()
        body = request.get_json(silent=True) or {}
        if str(body.get("confirm", "")).strip().lstrip("#") != str(scan_id):
            return jsonify({"error": f"confirmation does not match scan #{scan_id}"}), 400
        if manager.is_running(scan_id):
            return jsonify({"error": f"scan #{scan_id} is still running"}), 409
        try:
            result = delete_scan(cfg, scan_id)
        except LookupError as exc:
            return jsonify({"error": str(exc)}), 404
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(result)

    @app.get("/api/scans/<int:scan_id>/logs")
    def api_scan_logs(scan_id: int):
        if not store.get_scan(scan_id):
            abort(404)
        return jsonify(store.logs(scan_id, request.args.get("after", 0, type=int), 500,
                                  request.args.get("source") or None))

    @app.route("/export/<int:scan_id>.json")
    def export_json(scan_id: int):
        scan, findings = load(scan_id)
        body = json.dumps({"scan": {k: v for k, v in scan.items() if k != "runs"} | {"runs": [
            {k: r[k] for k in ("scanner", "scan_type", "status", "exit_code", "duration_s", "tool_version",
                               "error", "findings_count")} for r in scan["runs"]]},
            "findings": [f.to_dict(include_raw=request.args.get("raw") == "1") for f in findings]}, indent=2, default=str)
        return Response(body, mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=smartvuln-scan-{scan_id}.json"})

    @app.route("/report/<int:scan_id>.html")
    def html_report(scan_id: int):
        scan, findings = load(scan_id)
        prev = store.previous_scan_id(scan_id)
        summary = None
        if prev:
            summary = compare_scans(store.findings(prev), findings, store.run_statuses(prev),
                                    store.run_statuses(scan_id)).summary()
        return Response(render_html_report(scan, findings, summary), mimetype="text/html")

    @app.route("/report/compare/<int:baseline>/<int:current>.html")
    def html_compare(baseline: int, current: int):
        b, c = store.get_scan(baseline), store.get_scan(current)
        if not b or not c or b["status"] not in FINISHED or c["status"] not in FINISHED:
            abort(404)
        cmp = compare_scans(store.findings(baseline), store.findings(current),
                            store.run_statuses(baseline), store.run_statuses(current))
        return Response(render_comparison_html(b, c, cmp), mimetype="text/html")

    @app.route("/raw/<int:scan_id>/<name>")
    def raw_report(scan_id: int, name: str):
        scan = store.get_scan(scan_id) or abort(404)
        allowed = {Path(p).name: Path(p) for r in scan["runs"] for p in r["raw_reports"]}
        path = allowed.get(name)  # only files registered for this scan - no path traversal
        if not path or not path.is_file():
            abort(404)
        return Response(path.read_text(encoding="utf-8"), mimetype="application/json")

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------- helpers
def _histogram(scores: list[float]) -> list[int]:
    bins = [0] * 10
    for s in scores:
        bins[min(9, int(s // 10))] += 1
    return bins


def _group_types(f: Finding, by_id: dict[str, Finding]) -> set[str]:
    return {f.scan_type} | {by_id[i].scan_type for i in f.related_ids if i in by_id}


def _match(f: Finding, flt: dict[str, str]) -> bool:
    if flt["severity"] and f.severity != flt["severity"]:
        return False
    for key, attr in (("scanner", "scanner"), ("scan_type", "scan_type"), ("category", "category"),
                      ("correlation", "correlation_status"), ("triage", "triage_status"), ("priority", "priority")):
        if flt[key] and getattr(f, attr) != flt[key]:
            return False
    if flt["ident"]:
        ident = flt["ident"].upper()
        if not any(ident in x.upper() for x in f.cwe + f.cve):
            return False
    if flt["q"]:
        q = flt["q"].lower()
        blob = " ".join(str(x) for x in (f.title, f.rule_id, f.location, f.description, f.package_name, f.application)).lower()
        if q not in blob:
            return False
    return True


def _source_snippet(cfg: dict[str, Any], f: Finding, context: int = 3) -> list[tuple[int, str, bool]] | None:
    """A few lines of source around a SAST finding (secrets masked)."""
    if not f.file_path or not f.line_start or f.category == "vulnerable-dependency":
        return None
    root = resolve(cfg["source"]["path"]).resolve()
    path = (root / f.file_path).resolve()
    if root not in path.parents or not path.is_file():
        return None
    from ..engine.normalize import mask_secret
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start, end = max(1, f.line_start - context), min(len(lines), (f.line_end or f.line_start) + context)
    return [(n, mask_secret(lines[n - 1])[:300], f.line_start <= n <= (f.line_end or f.line_start))
            for n in range(start, end + 1)]
