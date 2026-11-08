"""Scanner adapter error handling (no Docker needed: execution is simulated)."""

import json
import sys
from pathlib import Path

import pytest

from smartvuln.config import load_config
from smartvuln.scanners import base
from smartvuln.scanners.base import CommandResult, run_command
from smartvuln.scanners.semgrep import SemgrepAdapter
from smartvuln.scanners.trivy import TrivyAdapter
from smartvuln.scanners.zap import TargetNotAllowed, ZapAdapter, build_plan, check_target_allowed


@pytest.fixture
def cfg(tmp_path):
    c = load_config()
    c["source"]["path"] = str(Path(__file__).parent / "fixtures" / "mini_app")
    return c


@pytest.fixture
def docker_ok(monkeypatch):
    monkeypatch.setattr(base, "docker_available", lambda: (True, "test"))


def _fake_run(monkeypatch, write: dict | str | None, exit_code=0, timed_out=False, stderr=""):
    calls = []

    def fake(cmd, timeout_s, container_name=None, cwd=None, on_line=None):
        calls.append(cmd)
        out = [a for a in cmd if a.startswith("/out/")]
        mount = next(a for a in cmd if "target=/out" in a or "target=/zap/wrk" in a)
        host_dir = Path(mount.split("source=")[1].split(",")[0])
        if write is not None and out:
            name = out[0].split("/")[-1]
            (host_dir / name).write_text(write if isinstance(write, str) else json.dumps(write))
        return CommandResult(None if timed_out else exit_code, "stdout", stderr, 1.0, timed_out,
                             "timed out after 1s" if timed_out else "")
    monkeypatch.setattr(base, "run_command", fake)
    return calls


def test_nonzero_exit_keeps_report(monkeypatch, cfg, tmp_path, docker_ok):
    _fake_run(monkeypatch, {"results": [], "errors": [], "version": "1.2.3"}, exit_code=1)
    run = SemgrepAdapter(cfg["semgrep"], cfg, tmp_path).run()
    assert run.status == "success" and run.exit_code == 1
    assert run.raw_report_paths and Path(run.raw_report_paths[0]).is_file()
    assert run.tool_version == "1.2.3"


def test_tool_errors_degrade_status(monkeypatch, cfg, tmp_path, docker_ok):
    _fake_run(monkeypatch, {"results": [], "errors": [{"level": "error", "type": "Timeout", "message": "x"},
                                                       {"level": "warn", "type": "Syntax", "message": "y"}]})
    run = SemgrepAdapter(cfg["semgrep"], cfg, tmp_path).run()
    assert run.status == "completed_with_errors" and "Timeout" in run.error and "Syntax" not in run.error


def test_missing_report_is_failure(monkeypatch, cfg, tmp_path, docker_ok):
    _fake_run(monkeypatch, None, exit_code=2, stderr="fatal: bad config")
    run = SemgrepAdapter(cfg["semgrep"], cfg, tmp_path).run()
    assert run.status == "failed" and "no parseable report" in run.error
    assert "fatal: bad config" in run.stderr_tail


def test_corrupt_report_is_failure(monkeypatch, cfg, tmp_path, docker_ok):
    _fake_run(monkeypatch, "{truncated")
    assert SemgrepAdapter(cfg["semgrep"], cfg, tmp_path).run().status == "failed"


def test_timeout_status(monkeypatch, cfg, tmp_path, docker_ok):
    _fake_run(monkeypatch, None, timed_out=True)
    run = SemgrepAdapter(cfg["semgrep"], cfg, tmp_path).run()
    assert run.status == "timeout" and "timed out" in run.error


def test_partial_multi_job_is_completed_with_errors(monkeypatch, cfg, tmp_path, docker_ok):
    state = {"n": 0}

    def fake(cmd, timeout_s, container_name=None, cwd=None, on_line=None):
        state["n"] += 1
        if state["n"] == 1:  # image job ok, fs job fails
            (tmp_path / "trivy-image.json").write_text(json.dumps({"SchemaVersion": 2, "Results": []}))
            return CommandResult(0, "", "", 1.0)
        return CommandResult(1, "", "boom", 1.0)
    monkeypatch.setattr(base, "run_command", fake)
    run = TrivyAdapter(cfg["trivy"], cfg, tmp_path).run()
    assert run.status == "completed_with_errors" and len(run.raw_report_paths) == 1


def test_docker_unavailable(monkeypatch, cfg, tmp_path):
    monkeypatch.setattr(base, "docker_available", lambda: (False, "docker daemon not reachable"))
    run = TrivyAdapter(cfg["trivy"], cfg, tmp_path).run()
    assert run.status == "failed" and "not reachable" in run.error


def test_disabled_scanner_skipped(cfg, tmp_path):
    cfg["semgrep"]["enabled"] = False
    assert SemgrepAdapter(cfg["semgrep"], cfg, tmp_path).run().status == "skipped"


def test_missing_source_skipped(cfg, tmp_path, docker_ok):
    cfg["source"]["path"] = str(tmp_path / "nope")
    run = SemgrepAdapter(cfg["semgrep"], cfg, tmp_path).run()
    assert run.status == "skipped" and "not found" in run.error


def test_external_target_refused(cfg, tmp_path, docker_ok):
    with pytest.raises(TargetNotAllowed):
        check_target_allowed("https://example.com", cfg["target"]["allowed_hosts"])
    check_target_allowed("https://example.com", [], allow_external=True)
    cfg["target"]["url"] = "https://example.com"
    run = ZapAdapter(cfg["zap"], cfg, tmp_path).run()
    assert run.status == "skipped" and "Refusing" in run.error


def test_unhealthy_target_skipped(monkeypatch, cfg, tmp_path, docker_ok):
    import smartvuln.scanners.zap as zap
    monkeypatch.setattr(zap, "wait_until_healthy", lambda url, t: (False, "connection refused"))
    run = ZapAdapter(cfg["zap"], cfg, tmp_path).run()
    assert run.status == "skipped" and "health check failed" in run.error


def test_zap_plan_profiles(cfg):
    targeted = build_plan("http://juice-shop:3000/", cfg["zap"])
    types = [j["type"] for j in targeted["jobs"]]
    assert types[0] == "requestor" and "activeScan" in types and types.count("report") == 2
    seeds = targeted["jobs"][0]["requests"]
    assert any(r["method"] == "POST" and r["url"].endswith("/rest/user/login") for r in seeds)
    baseline = build_plan("http://juice-shop:3000", {**cfg["zap"], "profile": "baseline"})
    assert "activeScan" not in [j["type"] for j in baseline["jobs"]]


def test_semgrep_command_mounts_custom_rules(cfg, tmp_path):
    job = SemgrepAdapter(cfg["semgrep"], cfg, tmp_path).jobs()[0]
    assert "--metrics=off" in job.cmd and "--json" in job.cmd
    assert any(a.startswith("/rules") for a in job.cmd)
    assert "data/static/codefixes" in job.cmd


def test_run_command_real_timeout_and_missing_binary():
    r = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=0.5)
    assert r.timed_out and r.exit_code is None
    r = run_command(["definitely-not-a-real-binary-xyz"], timeout_s=5)
    assert r.exit_code is None and "not found" in r.error


def test_secret_masking_in_tails():
    assert "ghp_****" not in base.tail("token ghp_ABCDEFGHIJKLMNOP1234567890")
    assert "ghp_AB****[masked]" in base.tail("token ghp_ABCDEFGHIJKLMNOP1234567890")
    assert base.tail("java.util.prefs.FileSystemPreferences") == "java.util.prefs.FileSystemPreferences"
    assert base.tail("starting container smartvuln-trivy-fs-3cc71a1f") == "starting container smartvuln-trivy-fs-3cc71a1f"
    url = "see https://trivy.dev/docs/v0.76/guide/scanner/vulnerability#severity"
    assert base.tail(url) == url
    pem = "MIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGz/qLpXvJXlxxW8iMz0EaM4BKUqYsIa"
    assert "DNwqLEe9wgTX" not in base.tail(pem)
