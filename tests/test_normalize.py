from smartvuln.engine.normalize import mask_secret, normalize, normalize_path
from smartvuln.engine.taxonomy import categorize, parse_cwes


def test_semgrep_normalization(semgrep_report):
    fs = normalize("semgrep", semgrep_report, "juice-shop")
    assert len(fs) == 5
    f = fs[0]
    assert f.scanner == "semgrep" and f.scan_type == "SAST"
    assert f.cwe == ["CWE-89"] and f.category == "sql-injection"
    assert f.severity == "high" and f.confidence == "high"
    assert f.file_path == "routes/search.ts" and f.line_start == 23
    assert f.evidence == ""  # "requires login" placeholder is not evidence
    assert f.raw["check_id"].endswith("raw-query-interpolation")
    assert f.exploitability_hint == "rule likelihood: high"
    # container mount prefix stripped
    assert fs[1].file_path == "routes/search.ts"
    # confidence absent -> None, never invented
    assert fs[2].confidence is None and fs[2].category == "weak-crypto"


def test_semgrep_secret_evidence_is_masked(semgrep_report):
    f = normalize("semgrep", semgrep_report, "app")[3]
    assert f.category == "hardcoded-secret"
    assert "MIICXA****[masked]" in f.evidence
    assert "DNwqLEe9wgTXCbC7" not in f.evidence


def test_zap_normalization(zap_report):
    fs = normalize("zap", zap_report, "juice-shop")
    sqli = [f for f in fs if f.rule_id == "zap-40018"][0]
    assert sqli.scan_type == "DAST" and sqli.severity == "high" and sqli.confidence == "medium"
    assert sqli.parameter == "q" and sqli.http_method == "GET"
    assert sqli.category == "sql-injection"
    assert sqli.description == "SQL injection may be possible."  # HTML stripped
    assert sqli.exploitability_hint == "active attack payload succeeded"
    csp = [f for f in fs if f.rule_id == "zap-10038"]
    assert len(csp) == 2  # duplicate instance on "/" collapsed, /ftp kept
    assert all(c.exploitability_hint is None for c in csp)  # passive -> no exploitability claim
    ts = [f for f in fs if f.rule_id == "zap-10096"][0]
    assert ts.severity == "info" and ts.confidence == "low"


def test_trivy_normalization(trivy_report):
    fs = normalize("trivy", trivy_report, "juice-shop")
    vulns = [f for f in fs if f.category == "vulnerable-dependency"]
    assert len(vulns) == 3
    jwt = vulns[0]
    assert jwt.cve == ["CVE-2015-9235", "GHSA-c7hr-j4mj-j2w6"]
    assert jwt.cvss_score == 9.8 and jwt.fixed_version == "4.2.2"
    assert jwt.confidence is None  # Trivy gives no confidence
    assert jwt.file_path == "node_modules/jsonwebtoken/package.json"
    secret = [f for f in fs if f.rule_id == "secret:private-key"][0]
    assert secret.file_path == "lib/insecurity.ts" and secret.line_start == 22
    assert "DNwqLEe9wgTXCbC7" not in secret.evidence and "DNwqLEe9wgTXCbC7" not in str(secret.raw)
    mis = [f for f in fs if f.rule_id.startswith("misconfig:")]
    assert len(mis) == 1  # PASS checks ignored


def test_trivy_cvss_follows_severity_source():
    rep = {"Results": [{"Target": "os", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "glibc", "InstalledVersion": "1", "Severity": "LOW",
         "SeveritySource": "debian", "CVSS": {"nvd": {"V3Score": 9.8}}},
        {"VulnerabilityID": "CVE-2", "PkgName": "lodash", "InstalledVersion": "1", "Severity": "HIGH",
         "SeveritySource": "ghsa", "CVSS": {"nvd": {"V3Score": 9.8}, "ghsa": {"V3Score": 7.4}}}]}]}
    a, b = normalize("trivy", rep, "app")
    assert a.cvss_score is None     # debian rated it LOW and gives no CVSS -> NVD 9.8 not mixed in
    assert b.cvss_score == 7.4


def test_fingerprint_stable_and_location_based(semgrep_report):
    a = normalize("semgrep", semgrep_report, "app", detected_at="2026-01-01T00:00:00")
    b = normalize("semgrep", semgrep_report, "app", detected_at="2026-02-02T00:00:00")
    assert [f.fingerprint for f in a] == [f.fingerprint for f in b]
    assert len({f.fingerprint for f in a}) == len(a)


def test_taxonomy_helpers():
    assert parse_cwes(["CWE-89: SQL", "cwe-89", 79, "-1", None]) == ["CWE-89", "CWE-79"]
    assert categorize([], "Content Security Policy (CSP) Header Not Set") == "missing-security-header"
    assert categorize(["CWE-999999"], "nothing matches") == "other"
    assert normalize_path("/src/./routes/a.ts") == "routes/a.ts"
    assert mask_secret("short") == "short"


def test_unknown_scanner_rejected():
    import pytest
    with pytest.raises(ValueError):
        normalize("nessus", {}, "app")
