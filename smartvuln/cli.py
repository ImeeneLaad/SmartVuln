"""Command-line interface: ``python -m smartvuln <command>``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .config import cfg_for_target, load_config, resolve, target_ids
from .engine.triage import TriageDecision
from .models import SEVERITY_RANK


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")


def cmd_scan(args, cfg) -> int:
    from .orchestrator import run_scan, store_for
    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    unknown = set(scanners) - {"semgrep", "trivy", "zap"}
    if unknown:
        print(f"unknown scanner(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    scan_id = run_scan(cfg_for_target(cfg, args.target), scanners, args.label, args.allow_external)
    return _print_scan_and_gate(store_for(cfg), scan_id, args.fail_on)


def cmd_import(args, cfg) -> int:
    from .orchestrator import import_reports, store_for
    scan_id = import_reports(cfg_for_target(cfg, args.target), args.raw_dir, args.label, is_demo=args.demo)
    return _print_scan_and_gate(store_for(cfg), scan_id, None)


def _print_scan_and_gate(store, scan_id: int, fail_on: str | None) -> int:
    scan = store.get_scan(scan_id)
    print(f"\nScan #{scan_id}: {scan['status']}  ->  {scan['scan_dir']}")
    for r in scan["runs"]:
        print(f"  {r['scanner']:8} {r['status']:22} {r['findings_count']:5} findings  {(r['error'] or '')[:100]}")
    st = scan["stats"]
    print(f"  {st.get('total', 0)} findings, {st.get('unique_issues', 0)} unique issues, "
          f"{st.get('correlation', {}).get('multi_scanner_groups', 0)} multi-scanner groups")
    if fail_on:  # optional CI gate - off by default so reports are always collected
        threshold = SEVERITY_RANK[fail_on]
        hits = [f for f in store.findings(scan_id) if f.is_group_primary and SEVERITY_RANK.get(f.severity, 0) >= threshold
                and f.triage_status != "false_positive"]
        if hits:
            print(f"Gate: {len(hits)} unique issue(s) at or above '{fail_on}'")
            return 1
    return 0


def cmd_targets(args, cfg) -> int:
    for tid in target_ids(cfg):
        c = cfg_for_target(cfg, tid)
        print(f"{tid:12} {c['general'].get('display_name', tid):32} {c['target']['url']:28} {c['source']['path']}")
    return 0


def cmd_list(args, cfg) -> int:
    from .orchestrator import store_for
    for s in store_for(cfg).list_scans(args.limit):
        runs = " ".join(f"{r['scanner']}={r['status']}" for r in s["runs"])
        print(f"#{s['id']:<4} {s['started_at']}  {s['status']:10} {'DEMO ' if s['is_demo'] else ''}"
              f"{s['stats'].get('total', 0):5} findings  {runs}  {s['label'] or ''}")
    return 0


def cmd_compare(args, cfg) -> int:
    from .orchestrator import comparison_for, store_for
    store = store_for(cfg)
    base, cmp = comparison_for(store, args.current, args.baseline)
    if not cmp:
        print("No baseline scan to compare with.", file=sys.stderr)
        return 1
    data = {"baseline_scan": base, "current_scan": args.current, **cmp.to_dict()}
    if args.out:
        Path(args.out).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"written {args.out}")
    print(json.dumps({"baseline_scan": base, "current_scan": args.current, **cmp.summary(),
                      "coverage_changes": cmp.coverage_changes}, indent=2))
    return 0


def cmd_report(args, cfg) -> int:
    from .orchestrator import store_for, write_reports
    store = store_for(cfg)
    scan = store.get_scan(args.scan_id)
    if not scan:
        print("scan not found", file=sys.stderr)
        return 1
    for kind, path in write_reports(cfg, store, args.scan_id, Path(scan["scan_dir"])).items():
        print(f"{kind:16} {path}")
    return 0


def cmd_reanalyze(args, cfg) -> int:
    from .orchestrator import reanalyze
    for sid in args.scan_ids:
        try:
            st = reanalyze(cfg, sid)
        except ValueError as exc:
            print(f"#{sid}: {exc}", file=sys.stderr)
            return 1
        print(f"#{sid}: {st['total']} findings, {st['unique_issues']} unique issues")
    return 0


def cmd_delete(args, cfg) -> int:
    from .orchestrator import delete_scan, store_for
    scan = store_for(cfg).get_scan(args.scan_id)
    if not scan:
        print(f"scan #{args.scan_id} does not exist", file=sys.stderr)
        return 1
    if not args.yes:
        print(f"Would delete scan #{scan['id']} ({scan['application']}, '{scan['label']}', {scan['started_at']}). "
              "Re-run with --yes to confirm.", file=sys.stderr)
        return 2
    try:
        r = delete_scan(cfg, args.scan_id)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"deleted scan #{r['deleted']}: {r['findings_removed']} findings, report folder removed: {r['folder_removed']}"
          + (f", comparison report regenerated for #{r['reports_updated'][0]}" if r["reports_updated"] else ""))
    return 0


def cmd_triage(args, cfg) -> int:
    from .orchestrator import store_for
    store = store_for(cfg)
    try:
        store.set_triage(TriageDecision(args.fingerprint, args.status, args.note, args.analyst))
    except ValueError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 2
    print(f"{args.fingerprint} -> {args.status}")
    return 0


def cmd_health(args, cfg) -> int:
    cfg = cfg_for_target(cfg, args.target)
    from .scanners.base import docker_available
    from .scanners.zap import wait_until_healthy
    ok, info = docker_available()
    print(f"docker: {'ok ' + info if ok else 'NOT AVAILABLE - ' + info}")
    src = resolve(cfg["source"]["path"])
    print(f"source: {src} {'ok' if src.is_dir() else 'MISSING (run scripts/fetch_target.sh)'}")
    healthy, msg = wait_until_healthy(cfg["target"]["healthcheck_url"], args.timeout)
    print(f"target: {cfg['target']['healthcheck_url']} {'ok ' + msg if healthy else 'NOT READY - ' + msg}")
    return 0 if ok and healthy else 1


def cmd_serve(args, cfg) -> int:
    from .app import create_app
    create_app(cfg).run(host=args.host, port=args.port, debug=False)
    return 0


def cmd_evaluate(args, cfg) -> int:
    from .evaluation import evaluate, format_report
    from .orchestrator import store_for
    store = store_for(cfg)
    scan_id = args.scan_id or store.latest_scan_id(include_demo=False)
    if not scan_id:
        print("no real scan available", file=sys.stderr)
        return 1
    result = evaluate(store.findings(scan_id), resolve(args.ground_truth), store.run_statuses(scan_id))
    result["scan_id"] = scan_id
    text = format_report(result)
    print(text)
    if args.out:
        out = Path(args.out)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        out.with_suffix(".md").write_text(text, encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="smartvuln", description="SmartVuln - SAST/DAST/SCA correlation platform")
    p.add_argument("--config", help="path to smartvuln.toml")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run scanners and analyze the results")
    s.add_argument("--target", help="target id from config (default: the default target)")
    s.add_argument("--scanners", default="semgrep,trivy,zap")
    s.add_argument("--label", default="")
    s.add_argument("--allow-external", action="store_true", help="permit DAST targets outside target.allowed_hosts")
    s.add_argument("--fail-on", choices=list(SEVERITY_RANK), help="exit 1 if a unique issue reaches this severity")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("import", help="analyze existing raw reports from a folder")
    s.add_argument("--target", help="target id from config (default: the default target)")
    s.add_argument("raw_dir")
    s.add_argument("--label", default="")
    s.add_argument("--demo", action="store_true", help="flag the scan as demonstration fixtures")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("targets", help="list configured scan targets")
    s.set_defaults(fn=cmd_targets)

    s = sub.add_parser("list", help="list scan history")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser("compare", help="compare a scan with a baseline (default: previous scan)")
    s.add_argument("current", type=int)
    s.add_argument("--baseline", type=int)
    s.add_argument("--out")
    s.set_defaults(fn=cmd_compare)

    s = sub.add_parser("report", help="(re)generate JSON/HTML reports for a scan")
    s.add_argument("scan_id", type=int)
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("reanalyze", help="re-run the analysis engine on stored raw reports of finished scans")
    s.add_argument("scan_ids", nargs="+", type=int)
    s.set_defaults(fn=cmd_reanalyze)

    s = sub.add_parser("delete", help="delete a scan with its findings, logs and report folder")
    s.add_argument("scan_id", type=int)
    s.add_argument("--yes", action="store_true", help="confirm the deletion")
    s.set_defaults(fn=cmd_delete)

    s = sub.add_parser("triage", help="record an analyst verdict for a finding fingerprint")
    s.add_argument("fingerprint")
    s.add_argument("status", choices=["confirmed", "false_positive", "needs_verification"])
    s.add_argument("--note", required=True)
    s.add_argument("--analyst", required=True)
    s.set_defaults(fn=cmd_triage)

    s = sub.add_parser("health", help="check docker, source checkout and target readiness")
    s.add_argument("--target", help="target id from config (default: the default target)")
    s.add_argument("--timeout", type=float, default=10)
    s.set_defaults(fn=cmd_health)

    s = sub.add_parser("serve", help="start the dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("evaluate", help="precision/recall against the manually verified ground truth")
    s.add_argument("scan_id", nargs="?", type=int)
    s.add_argument("--ground-truth", default="evaluation/ground_truth.json")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_evaluate)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)
    cfg = load_config(args.config)
    return int(args.fn(args, cfg) or 0)
