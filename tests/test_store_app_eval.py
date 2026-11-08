"""SQLite store, orchestrator import path, dashboard routes and evaluation."""

import json
from pathlib import Path

import pytest

from smartvuln.app import create_app
from smartvuln.config import load_config
from smartvuln.engine.triage import TriageDecision
from smartvuln.evaluation import evaluate, format_report
from smartvuln.models import Finding
from smartvuln.orchestrator import import_reports, store_for

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def cfg(tmp_path):
    c = load_config()
    c["general"]["database"] = str(tmp_path / "t.db")
    c["general"]["data_dir"] = str(tmp_path / "data")
    c["source"]["path"] = str(FIX / "mini_app")
    return c


@pytest.fixture
def two_scans(cfg, tmp_path):
    first = import_reports(cfg, FIX, "first", is_demo=True)
    # second scan: drop the ZAP report and change one Semgrep severity
    d2 = tmp_path / "raw2"
    d2.mkdir()
    sg = json.loads((FIX / "semgrep_sample.json").read_text())
    sg["results"][2]["extra"]["severity"] = "ERROR"
    sg["results"].pop(0)
    (d2 / "semgrep.json").write_text(json.dumps(sg))
    (d2 / "trivy-image.json").write_text((FIX / "trivy_sample.json").read_text())
    second = import_reports(cfg, d2, "second", is_demo=True)
    return first, second


def test_import_persists_and_reports(cfg, two_scans):
    store = store_for(cfg)
    first, second = two_scans
    scan = store.get_scan(first)
    assert scan["is_demo"] == 1 and scan["status"] == "completed"
    assert {r["scanner"]: r["status"] for r in scan["runs"]} == {"semgrep": "success", "trivy": "success", "zap": "success"}
    assert len(store.findings(first)) == scan["stats"]["total"]
    out = Path(scan["scan_dir"])
    for name in ("normalized-findings.json", "report.html", "summary.md"):
        assert (out / name).is_file()
    assert "DEMONSTRATION FIXTURES" in (out / "report.html").read_text(encoding="utf-8")
    assert (Path(store.get_scan(second)["scan_dir"]) / "comparison.json").is_file()


def test_comparison_after_import(cfg, two_scans):
    from smartvuln.orchestrator import comparison_for
    store = store_for(cfg)
    first, second = two_scans
    base, cmp = comparison_for(store, second)
    s = cmp.summary()
    assert base == first
    assert s["severity_increased"] == 1          # md5 rule WARNING -> ERROR
    assert s["resolved"] == 1                    # removed semgrep finding; semgrep ran in both
    assert s["not_retested"] >= 4 and all(f.scanner == "zap" for f in cmp.not_retested)  # zap skipped
    assert any(c["scanner"] == "zap" and c["current_status"] == "skipped" for c in cmp.coverage_changes)


def test_triage_persists_across_scans(cfg, two_scans):
    store = store_for(cfg)
    first, second = two_scans
    f = next(x for x in store.findings(first) if x.rule_id == "secret:private-key")
    store.set_triage(TriageDecision(f.fingerprint, "confirmed", "Key verified in lib/insecurity.ts line 21", "tester"))
    g = next(x for x in store.findings(second) if x.fingerprint == f.fingerprint)
    assert g.triage_status == "confirmed" and "tester" in g.triage_reason
    with pytest.raises(ValueError):
        store.set_triage(TriageDecision(f.fingerprint, "false_positive", "short", "tester"))


def test_dashboard_routes(cfg, two_scans):
    app = create_app(cfg)
    c = app.test_client()
    first, second = two_scans
    for url in ["/", f"/?scan={first}", "/findings", f"/findings?scan={first}&severity=high&primary=1",
                f"/findings?scan={first}&ident=CWE-89", "/scans", "/compare", f"/compare?baseline={first}&current={second}",
                "/reports", f"/report/{first}.html", f"/report/compare/{first}/{second}.html", "/healthz"]:
        r = c.get(url)
        assert r.status_code == 200, url
    assert b"Demonstration fixtures" in c.get("/").data
    r = c.get(f"/export/{first}.json")
    data = json.loads(r.data)
    assert len(data["findings"]) > 0 and "raw" not in data["findings"][0]
    store = store_for(cfg)
    fid = store.findings(first)[0].id
    assert c.get(f"/findings/{fid}?scan={first}").status_code == 200
    assert c.get(f"/raw/{first}/semgrep_sample.json").status_code == 200
    assert c.get(f"/raw/{first}/..%2F..%2Fsecret").status_code == 404
    # triage POST without CSRF token is rejected
    assert c.post(f"/findings/{fid}/triage", data={"scan": first, "status": "confirmed"}).status_code == 400
    # valid submission with the session's CSRF token is recorded
    with c.session_transaction() as sess:
        sess["csrf"] = "tok"
    r = c.post(f"/findings/{fid}/triage", data={"csrf": "tok", "scan": first, "status": "false_positive",
                                                "analyst": "tester", "note": "handler rejects '/' so no traversal"})
    assert r.status_code == 302
    assert next(f for f in store.findings(first) if f.id == fid).triage_status == "false_positive"
    r = c.post(f"/findings/{fid}/triage", data={"csrf": "tok", "scan": first, "status": "confirmed",
                                                "analyst": "tester", "note": "short"}, follow_redirects=True)
    assert b"justification" in r.data  # rejected with a message, verdict unchanged
    assert next(f for f in store.findings(first) if f.id == fid).triage_status == "false_positive"


def test_dashboard_empty(cfg):
    assert b"No scans yet" in create_app(cfg).test_client().get("/").data


def _f(**kw):
    f = Finding(**{"scanner": "semgrep", "scan_type": "SAST", "rule_id": "custom.r", "title": "t", **kw})
    f.compute_fingerprint()
    return f


def test_evaluation_metrics(tmp_path):
    gt = {"source_ref": "t", "line_tolerance": 2, "vulnerabilities": [
        {"id": "A", "title": "sqli", "category": "sql-injection", "code": [{"file": "a.ts", "line": 10}],
         "endpoint": {"method": "GET", "path": "^/search$"}},
        {"id": "B", "title": "secret", "category": "hardcoded-secret", "code": [{"file": "b.ts", "line": 5}]}],
        "closed_world_scope": {"files": {"a.ts": ["sql-injection"], "c.ts": ["sql-injection"]}, "known_negatives": []}}
    p = tmp_path / "gt.json"
    p.write_text(json.dumps(gt))
    tp = _f(file_path="a.ts", line_start=11, category="sql-injection", group_id="G1")
    fp = _f(file_path="c.ts", line_start=1, category="sql-injection", group_id="G2")
    out_of_scope = _f(file_path="z.ts", line_start=1, category="xss", group_id="G3")
    dast = _f(scanner="zap", scan_type="DAST", rule_id="zap-40018", url="http://h/search?q=1", http_method="GET",
              category="sql-injection", group_id="G1")
    r = evaluate([tp, fp, out_of_scope, dast], p, {"semgrep": "success", "zap": "success"})
    assert r["recall"]["semgrep (all rules)"]["recall"] == 0.5
    assert r["recall"]["zap (DAST)"]["tp"] == 1 and r["recall"]["zap (DAST)"]["applicable"] == 1
    pr = r["precision_closed_world"]["semgrep (all rules)"]
    assert (pr["tp"], pr["fp"], pr["precision"]) == (1, 1, 0.5)  # out-of-scope finding not counted
    assert r["correlation"]["fully_correlated"] == 1 and r["correlation"]["wrong_merges"] == []
    assert "not computed" in r["precision_closed_world"]["zap (DAST)"]["note"]
    failed = evaluate([tp], p, {"semgrep": "success", "zap": "failed"})
    assert "not computed" in failed["recall"]["zap (DAST)"]["note"]
    not_run = evaluate([tp], p, {"semgrep": "success"})
    assert "not computed" in not_run["recall"]["zap (DAST)"]["note"]
    assert "not computed" in not_run["recall"]["trivy (secret scanner)"]["note"]
    assert "Recall" in format_report(r)
