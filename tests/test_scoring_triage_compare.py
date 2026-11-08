import pytest

from smartvuln.engine.compare import compare_scans
from smartvuln.engine.pipeline import analyze
from smartvuln.engine.scoring import DEFAULT_SCORING, merge_config, priority_for, score_finding
from smartvuln.engine.triage import TriageDecision, apply_decisions
from smartvuln.models import Finding


def _f(**kw) -> Finding:
    base = dict(scanner="semgrep", scan_type="SAST", rule_id="r", title="t", file_path="routes/a.ts", line_start=1)
    base.update(kw)
    f = Finding(**base)
    f.compute_fingerprint()
    return f


def _factor(f, name):
    return next((x for x in f.risk_factors if x["factor"] == name), None)


def test_base_and_confidence():
    f = score_finding(_f(severity="high", confidence="high"), DEFAULT_SCORING)
    assert f.risk_score == 70 and f.priority == "P2"
    g = score_finding(_f(severity="high", confidence=None), DEFAULT_SCORING)
    assert g.risk_score == pytest.approx(59.5)
    assert "NOT evidence" in _factor(g, "confidence")["reason"]


def test_no_invented_exploitability():
    f = score_finding(_f(severity="medium", confidence="high"), DEFAULT_SCORING)
    names = {x["factor"] for x in f.risk_factors}
    assert names == {"base", "confidence"}  # no data -> no bonus


def test_cvss_used_for_sca():
    f = score_finding(_f(scanner="trivy", scan_type="SCA", severity="critical", cvss_score=9.8,
                         category="vulnerable-dependency", file_path=None), DEFAULT_SCORING)
    assert _factor(f, "base")["value"] == pytest.approx(98)
    assert f.risk_score == pytest.approx(83.3) and f.priority == "P1"


def test_context_adjustments():
    f = _f(severity="high", confidence="high", exploitability_hint="rule likelihood: high")
    f.correlation_status = "multi_scanner"
    score_finding(f, DEFAULT_SCORING, handler_files={"routes/a.ts"})
    assert f.risk_score == 70 + 5 + 10 + 5
    t = score_finding(_f(severity="high", confidence="high", file_path="test/api/x.ts"), DEFAULT_SCORING)
    assert t.risk_score == 55
    d = score_finding(_f(scanner="zap", scan_type="DAST", severity="high", confidence="medium", file_path=None,
                         url="http://h/x", exploitability_hint="active attack payload succeeded"), DEFAULT_SCORING)
    assert d.risk_score == pytest.approx(59.5 + 10 + 5)


def test_score_clamped_and_config_override():
    cfg = merge_config({"adjustments": {"corroborated_multi_scanner": 50}})
    assert cfg["adjustments"]["observed_on_deployment"] == 5  # untouched defaults survive
    f = _f(severity="critical", confidence="high")
    f.correlation_status = "multi_scanner"
    assert score_finding(f, cfg).risk_score == 100
    assert priority_for(34.9, DEFAULT_SCORING["priority_bands"]) == "P4"


def test_false_positive_scores_zero():
    f = _f(severity="critical", confidence="high")
    f.triage_status = "false_positive"
    assert score_finding(f, DEFAULT_SCORING).risk_score == 0


def test_manual_triage_requires_justification():
    with pytest.raises(ValueError):
        TriageDecision("fp", "confirmed", "ok", "alice").validate()
    with pytest.raises(ValueError):
        TriageDecision("fp", "false_positive", "long enough justification", "").validate()
    with pytest.raises(ValueError):
        TriageDecision("fp", "likely_duplicate", "long enough justification", "a").validate()
    d = TriageDecision("x", "confirmed", "Reproduced with ' OR 1=1-- in the login form", "alice", "2026-11-07")
    d.validate()
    f = _f()
    f.fingerprint = "x"
    assert apply_decisions([f], {"x": d}) == 1 and f.triage_status == "confirmed"
    assert "alice" in f.triage_reason


def test_pipeline_never_auto_confirms(fixtures_dir):
    res = analyze({"semgrep": [fixtures_dir / "semgrep_sample.json"], "zap": [fixtures_dir / "zap_sample.json"],
                   "trivy": [fixtures_dir / "trivy_sample.json"]}, "app", source_root=fixtures_dir / "mini_app")
    states = {f.triage_status for f in res.findings}
    assert states <= {"needs_verification", "likely_duplicate"}
    assert res.stats()["total"] == len(res.findings)
    assert res.routes_mapped == 2


def test_pipeline_survives_broken_report(tmp_path, fixtures_dir):
    bad = tmp_path / "broken.json"
    bad.write_text("{not json")
    res = analyze({"semgrep": [bad, fixtures_dir / "semgrep_sample.json"]}, "app")
    assert len(res.parse_errors) == 1 and len(res.findings) == 5


# ------------------------------------------------------------------------------ comparison
def test_compare_new_resolved_persistent_severity():
    a = _f(rule_id="a", severity="medium")
    b = _f(rule_id="b", severity="low")
    c = _f(rule_id="c", severity="high")
    b2 = _f(rule_id="b", severity="high")
    d = _f(rule_id="d", severity="low")
    cmp = compare_scans([a, b, c], [b2, d], {"semgrep": "success"}, {"semgrep": "success"})
    s = cmp.summary()
    assert (s["new"], s["resolved"], s["persistent"], s["severity_increased"]) == (1, 2, 1, 1)
    assert cmp.severity_changes[0]["from"] == "low" and cmp.severity_changes[0]["to"] == "high"


def test_compare_dast_url_sampling_is_not_a_fix():
    def z(rule, path):
        return _f(scanner="zap", scan_type="DAST", rule_id=rule, url=f"http://h{path}", http_method="GET", file_path=None)
    csp_rest, csp_root = z("zap-10038", "/rest"), z("zap-10038", "/")
    redirect = z("zap-20019", "/redirect")
    sqli_new = z("zap-40018", "/rest/products/search")
    sast_gone = _f(rule_id="custom.sqli")
    cmp = compare_scans([csp_rest, redirect, sast_gone], [csp_root, sqli_new],
                        {"zap": "success", "semgrep": "success"}, {"zap": "success", "semgrep": "success"})
    assert cmp.not_observed == [csp_rest]            # CSP rule still fires on "/" -> not a fix
    assert set(f.rule_id for f in cmp.resolved) == {"zap-20019", "custom.sqli"}  # rule gone everywhere / SAST gone
    assert cmp.new_known_rule == {csp_root.fingerprint}  # new URL of a known rule
    s = cmp.summary()
    assert (s["new"], s["new_known_rule"], s["resolved"], s["not_observed"]) == (2, 1, 2, 1)
    d = cmp.to_dict()
    assert {n["known_rule"] for n in d["new"]} == {True, False}
    assert d["not_observed"][0]["location"] == "GET http://h/rest"


def test_compare_sast_line_shift_is_moved_not_new():
    old = [_f(rule_id="xss", file_path="routes/search.js", line_start=7),
           _f(rule_id="xss", file_path="routes/search.js", line_start=11),
           _f(rule_id="sqli", file_path="routes/products.js", line_start=12)]
    new = [_f(rule_id="xss", file_path="routes/search.js", line_start=10),   # same warning, shifted by an edit
           _f(rule_id="xss", file_path="routes/search.js", line_start=14),
           _f(rule_id="xss", file_path="routes/other.js", line_start=3)]     # genuinely new (other file)
    cmp = compare_scans(old, new, {"semgrep": "success"}, {"semgrep": "success"})
    s = cmp.summary()
    assert (s["moved"], s["new"], s["resolved"], s["persistent"]) == (2, 1, 1, 2)
    assert cmp.resolved[0].rule_id == "sqli"
    assert [(m["from_line"], m["to_line"]) for m in cmp.moved] == [(7, 10), (11, 14)]


def test_sca_fingerprint_ignores_installed_version():
    a = _f(scanner="trivy", scan_type="SCA", rule_id="CVE-2025-13465", package_name="lodash", package_version="4.17.15",
           file_path="package-lock.json")
    b = _f(scanner="trivy", scan_type="SCA", rule_id="CVE-2025-13465", package_name="lodash", package_version="4.17.21",
           file_path="package-lock.json")
    assert a.fingerprint == b.fingerprint          # CVE still applies after the upgrade -> remaining
    cmp = compare_scans([a], [b], {"trivy": "success"}, {"trivy": "success"})
    assert cmp.summary()["persistent"] == 1 and not cmp.resolved and not cmp.new


def test_compare_failed_scanner_is_not_resolved():
    z = _f(scanner="zap", scan_type="DAST", rule_id="zap-1", url="http://h/x", http_method="GET", file_path=None)
    s = _f(rule_id="s")
    cmp = compare_scans([z, s], [s], {"zap": "success", "semgrep": "success"},
                        {"zap": "failed", "semgrep": "success"})
    assert cmp.resolved == [] and cmp.not_retested == [z]
    assert cmp.coverage_changes == [{"scanner": "zap", "baseline_status": "success", "current_status": "failed",
                                     "baseline_findings": 1, "current_findings": 0}]
