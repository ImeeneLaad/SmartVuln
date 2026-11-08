from smartvuln.engine.correlation import correlate
from smartvuln.engine.normalize import normalize
from smartvuln.engine.routemap import build_route_map, handlers_for_url
from smartvuln.models import Finding


def _all(semgrep_report, zap_report, trivy_report):
    return (normalize("semgrep", semgrep_report, "app") + normalize("zap", zap_report, "app")
            + normalize("trivy", trivy_report, "app"))


def test_route_map(fixtures_dir):
    routes = build_route_map(fixtures_dir / "mini_app")
    assert {(r.method, r.path, r.handler_file) for r in routes} == {
        ("GET", "/rest/products/search", "routes/search.ts"),
        ("POST", "/rest/user/login", "routes/login.ts"),
    }  # '/ftp' handler is not imported from ./routes -> not mapped
    assert handlers_for_url(routes, "GET", "http://h:3000/rest/products/search?q=1") == {"routes/search.ts"}
    assert handlers_for_url(routes, "POST", "http://h/rest/products/search") == set()  # method must match
    assert handlers_for_url(routes, "GET", None) == set()


def test_sast_dast_correlation_via_route_map(fixtures_dir, semgrep_report, zap_report, trivy_report):
    fs = _all(semgrep_report, zap_report, trivy_report)
    res = correlate(fs, build_route_map(fixtures_dir / "mini_app"))
    by_rule = {f.rule_id: f for g in res.groups.values() for f in g}
    custom = by_rule["custom_rules.semgrep.smartvuln-sequelize-raw-query-interpolation"]
    zap_sqli = by_rule["zap-40018"]
    assert custom.group_id == zap_sqli.group_id
    assert custom.correlation_status == "multi_scanner"
    assert any(r.startswith("R3 endpoint-handler") for r in zap_sqli.correlation_reasons)
    # registry rule on line 24 joins via R2 (±2 lines, same category)
    assert by_rule["javascript.sequelize.security.audit.sequelize-injection-express"].group_id == custom.group_id
    # time-based ZAP SQLi on same param joins via R4
    assert by_rule["zap-40024"].group_id == custom.group_id
    assert res.summary()["sast_dast_groups"] >= 1


def test_no_merge_on_shared_cwe_or_severity_only(fixtures_dir, semgrep_report, zap_report, trivy_report):
    fs = _all(semgrep_report, zap_report, trivy_report)
    res = correlate(fs, build_route_map(fixtures_dir / "mini_app"))
    flat = {f.rule_id + (f.file_path or ""): f for g in res.groups.values() for f in g}
    # SQL rule in a test file shares CWE-89 + severity but not location -> stays separate
    test_sql = flat["test.ruletest/api/searchApiSpec.ts"]
    assert test_sql.correlation_status == "uncorrelated" and test_sql.related_ids == []
    # The two CSP instances (different URLs, same rule) are NOT merged
    csp = [f for g in res.groups.values() for f in g if f.rule_id == "zap-10038"]
    assert len({c.group_id for c in csp}) == 2


def test_sca_duplicate_and_secret_cross_tool(semgrep_report, trivy_report):
    fs = normalize("semgrep", semgrep_report, "app") + normalize("trivy", trivy_report, "app")
    res = correlate(fs)
    flat = [f for g in res.groups.values() for f in g]
    jwt = [f for f in flat if f.rule_id == "CVE-2015-9235"]
    assert len(jwt) == 2 and jwt[0].group_id == jwt[1].group_id
    assert jwt[0].correlation_status == "same_scanner_duplicate"
    assert sum(1 for f in jwt if f.triage_status == "likely_duplicate") == 1
    lodash = [f for f in flat if f.package_name == "lodash"][0]
    assert lodash.group_id != jwt[0].group_id  # same scanner + severity class != duplicate
    secret_semgrep = [f for f in flat if f.rule_id.endswith("hardcoded-jwt-private-key")][0]
    secret_trivy = [f for f in flat if f.rule_id == "secret:private-key"][0]
    assert secret_semgrep.group_id == secret_trivy.group_id
    assert secret_semgrep.correlation_status == "multi_scanner"


def test_provenance_preserved_and_exact_duplicates_collapsed():
    a = Finding(scanner="semgrep", scan_type="SAST", rule_id="r1", title="x", file_path="a.ts", line_start=1,
                category="xss", raw={"orig": 1})
    b = Finding(scanner="semgrep", scan_type="SAST", rule_id="r1", title="x", file_path="a.ts", line_start=1,
                category="xss", raw={"orig": 2})
    for f in (a, b):
        f.compute_fingerprint()
    res = correlate([a, b])
    assert res.summary()["findings"] == 1  # identical fingerprint = same record
    assert res.groups["G0001"][0].raw == {"orig": 1}


def test_one_primary_per_group(semgrep_report, zap_report, trivy_report, fixtures_dir):
    res = correlate(_all(semgrep_report, zap_report, trivy_report), build_route_map(fixtures_dir / "mini_app"))
    for members in res.groups.values():
        assert sum(1 for m in members if m.is_group_primary) == 1
