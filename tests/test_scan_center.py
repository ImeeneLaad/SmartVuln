"""Scan Center: API -> ScanManager -> orchestrator -> analysis -> reports.

Everything runs for real except the Docker boundary: ``run_command`` is replaced
by a stand-in that writes the hand-written fixture reports where the scanner
containers would write theirs and emits a few output lines.
"""

import json
import threading
import time
from pathlib import Path

import pytest

import smartvuln.scanners.base as base
import smartvuln.scanners.zap as zap
from smartvuln.app import create_app
from smartvuln.config import load_config
from smartvuln.database.store import Store
from smartvuln.scanners.base import CommandResult

FIX = Path(__file__).parent / "fixtures"
REPORTS = {"semgrep.json": "semgrep_sample.json", "trivy-image.json": "trivy_sample.json",
           "zap-report.json": "zap_sample.json"}


@pytest.fixture
def cfg(tmp_path):
    c = load_config()
    c["general"]["database"] = str(tmp_path / "t.db")
    c["general"]["data_dir"] = str(tmp_path / "data")
    c["source"]["path"] = str(FIX / "mini_app")
    return c


@pytest.fixture
def fake_docker(monkeypatch):
    gate = threading.Event()
    gate.set()
    import smartvuln.scan_manager as sm
    monkeypatch.setattr(base, "docker_available", lambda: (True, "test-engine"))
    monkeypatch.setattr(sm, "docker_available", lambda: (True, "test-engine"))
    monkeypatch.setattr(sm, "probe_url", lambda url, timeout=3.0: {"reachable": True, "detail": "HTTP 200"})
    monkeypatch.setattr(sm, "image_present", lambda img: True)
    monkeypatch.setattr(zap, "wait_until_healthy", lambda url, t: (True, "HTTP 200"))

    def fake_run(cmd, timeout_s, container_name=None, cwd=None, on_line=None):
        gate.wait(10)
        mount = next(a for a in cmd if "target=/out" in a or "target=/zap/wrk" in a)
        out_dir = Path(mount.split("source=")[1].split(",")[0])
        produced = [a.split("/")[-1] for a in cmd if a.startswith("/out/")] or ["zap-report.json"]
        for name in produced:
            src = REPORTS.get(name)
            (out_dir / name).write_text((FIX / src).read_text() if src else json.dumps({"Results": []}))
        if on_line:
            on_line("stderr", f"{container_name}: scanning (simulated container output)")
        return CommandResult(2 if "zap" in (container_name or "") else 0, "out", "", 0.1)

    monkeypatch.setattr(base, "run_command", fake_run)
    return gate


def _client(cfg):
    app = create_app(cfg)
    c = app.test_client()
    c.get("/scan")  # creates the session CSRF token
    with c.session_transaction() as s:
        token = s["csrf"]
    return app, c, token


def _wait(c, scan_id, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        s = c.get(f"/api/scans/{scan_id}").get_json()
        if s["status"] not in ("running",):
            return s
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


def test_initial_state_is_empty(cfg):
    _, c, _ = _client(cfg)
    home = c.get("/").data.decode()
    assert "No scans yet" in home and "Open the Scan Center" in home
    assert "No reports yet" in c.get("/reports").data.decode()
    assert "Two completed scans needed" in c.get("/compare").data.decode()
    assert "No scans yet" in c.get("/scans").data.decode()
    assert "No logs yet" in c.get("/logs").data.decode()
    assert c.get("/api/scans").get_json() == []
    page = c.get("/scan").data.decode()
    assert "Start scan" in page and "Semgrep" in page and "OWASP ZAP" in page and "Trivy" in page


def test_preflight_reports_real_checks(cfg, monkeypatch):
    import smartvuln.scan_manager as sm
    monkeypatch.setattr(sm, "docker_available", lambda: (True, "29.0"))
    monkeypatch.setattr(sm, "probe_url", lambda url, timeout=3.0: {"reachable": False, "detail": "connection refused"})
    monkeypatch.setattr(sm, "image_present", lambda img: True)
    _, c, _ = _client(cfg)
    p = c.get("/api/targets").get_json()
    assert p["target"]["id"] == "juice-shop" and p["target"]["source_present"] is True
    assert p["target"]["reachable"] is False
    assert p["scanners"]["zap"]["ready"] is False and "not reachable" in p["scanners"]["zap"]["notes"][0]
    assert p["scanners"]["semgrep"]["ready"] is True
    assert p["running_scan"] is None


def test_api_requires_csrf_and_valid_input(cfg):
    _, c, token = _client(cfg)
    assert c.post("/api/scans", json={"target": "juice-shop", "scanners": ["semgrep"]}).status_code == 400
    h = {"X-CSRF-Token": token}
    r = c.post("/api/scans", json={"target": "juice-shop", "scanners": ["nessus"]}, headers=h)
    assert r.status_code == 400 and "unknown scanner" in r.get_json()["error"]
    r = c.post("/api/scans", json={"target": "juice-shop", "scanners": []}, headers=h)
    assert r.status_code == 400
    r = c.post("/api/scans", json={"target": "example.com", "scanners": ["semgrep"]}, headers=h)
    assert r.status_code == 400 and "unknown target" in r.get_json()["error"]
    assert c.get("/api/scans").get_json() == []  # nothing was created


def test_full_scan_through_api(cfg, fake_docker):
    _, c, token = _client(cfg)
    r = c.post("/api/scans", json={"target": "juice-shop", "scanners": ["semgrep", "trivy", "zap"], "label": "t1"},
               headers={"X-CSRF-Token": token})
    assert r.status_code == 202
    sid = r.get_json()["scan_id"]
    s = _wait(c, sid)
    assert s["status"] == "completed" and s["progress"] == 1
    runs = {x["scanner"]: x for x in s["runs"]}
    assert {k: v["status"] for k, v in runs.items()} == {"semgrep": "success", "trivy": "success", "zap": "success"}
    assert runs["zap"]["exit_code"] == 2  # non-zero exit, report kept, still success
    assert runs["semgrep"]["findings_count"] == 5 and runs["zap"]["raw_reports"] == ["zap-report.json"]
    assert s["stats"]["total"] > 0
    assert {"report.html", "normalized-findings.json", "summary.md"} <= set(s["reports"])
    logs = c.get(f"/api/scans/{sid}/logs").get_json()
    sources = {l["source"] for l in logs}
    assert {"smartvuln", "semgrep", "trivy", "zap"} <= sources
    assert any("simulated container output" in l["message"] for l in logs)
    assert any("target is healthy" in l["message"] for l in logs)
    assert any("analysis done" in l["message"] for l in logs)
    after = logs[-1]["id"]
    assert c.get(f"/api/scans/{sid}/logs?after={after}").get_json() == []
    # pages now show this scan
    assert f"Scan #{sid}".encode() in c.get("/").data or b"Security overview" in c.get("/").data
    assert b"report.html" in c.get("/reports").data
    assert c.get(f"/reports/{sid}/report.html").status_code == 200
    assert c.get(f"/reports/{sid}/../../t.db").status_code == 404
    assert c.get(f"/logs?scan={sid}").status_code == 200
    log_files = Path(cfg["general"]["data_dir"]) / "scans" / f"{sid:04d}" / "logs"
    assert {"semgrep.log", "trivy.log", "zap.log", "smartvuln.log"} <= {p.name for p in log_files.iterdir()}
    assert c.get(f"/logs/{sid}/zap.log").status_code == 200


def test_concurrent_scan_refused_and_compare(cfg, fake_docker):
    _, c, token = _client(cfg)
    h = {"X-CSRF-Token": token}
    fake_docker.clear()  # hold the first scan inside its scanner
    first = c.post("/api/scans", json={"target": "juice-shop", "scanners": ["semgrep"]}, headers=h).get_json()["scan_id"]
    assert c.get(f"/api/scans/{first}").get_json()["status"] == "running"
    assert c.get("/api/targets").get_json()["running_scan"]["id"] == first
    r = c.post("/api/scans", json={"target": "juice-shop", "scanners": ["trivy"]}, headers=h)
    assert r.status_code == 409 and r.get_json()["running_scan"] == first
    assert b"running" in c.get("/scans").data
    fake_docker.set()
    assert _wait(c, first)["status"] == "completed"
    second = c.post("/api/scans", json={"target": "juice-shop", "scanners": ["semgrep"]}, headers=h).get_json()["scan_id"]
    assert _wait(c, second)["status"] == "completed"
    page = c.get(f"/compare?baseline={first}&current={second}").data.decode()
    assert "Remaining" in page and "Resolved" in page and "Two completed scans needed" not in page
    assert c.get(f"/compare?baseline={first}&current={first}").data.decode().count("Choose two different scans") == 1


def test_interrupted_scans_are_marked(cfg):
    store = Store(cfg["general"]["database"])
    sid = store.create_scan("juice-shop", "http://juice-shop:3000", "", "x", scanners=["semgrep"])
    store.add_pending_runs(sid, [("semgrep", "SAST")])
    create_app(cfg)  # a new server process starts
    s = store.get_scan(sid)
    assert s["status"] == "interrupted" and s["runs"][0]["status"] == "failed"


# ------------------------------------------------------------------------------ deletion
def _start(c, token, label="", scanners=("semgrep",)):
    r = c.post("/api/scans", json={"target": "juice-shop", "scanners": list(scanners), "label": label},
               headers={"X-CSRF-Token": token})
    assert r.status_code == 202, r.get_json()
    return _wait(c, r.get_json()["scan_id"])


def test_default_scan_name_is_numbered(cfg, fake_docker):
    _, c, token = _client(cfg)
    assert _start(c, token)["label"] == "Scan #1"
    assert _start(c, token, "Scan #2 - Before Fixes")["label"] == "Scan #2 - Before Fixes"
    assert _start(c, token)["label"] == "Scan #3"
    assert '"juice-shop": 4' in c.get("/scan").data.decode()  # next number suggested in the Scan Center


def test_delete_scan_removes_only_that_scan(cfg, fake_docker):
    from smartvuln.engine.triage import TriageDecision
    app, c, token = _client(cfg)
    store = app.extensions["smartvuln_store"]
    first, second = _start(c, token, "before"), _start(c, token, "after")
    d1 = Path(cfg["general"]["data_dir"]) / "scans" / f"{first['id']:04d}"
    d2 = Path(cfg["general"]["data_dir"]) / "scans" / f"{second['id']:04d}"
    assert (d2 / "comparison.json").is_file()  # second was compared against first
    fp = store.findings(first["id"])[0].fingerprint
    store.set_triage(TriageDecision(fp, "confirmed", "verified manually in the lab", "tester"))
    n_second = len(store.findings(second["id"]))
    logs_second = len(store.logs(second["id"]))

    h = {"X-CSRF-Token": token}
    url = f"/api/scans/{first['id']}"
    assert c.delete(url, json={"confirm": first["id"]}).status_code == 400            # no CSRF token
    assert c.delete(url, json={"confirm": second["id"]}, headers=h).status_code == 400  # wrong confirmation
    assert c.delete(url, json={}, headers=h).status_code == 400                        # no confirmation
    assert c.get(url).status_code == 200                                               # still there

    r = c.delete(url, json={"confirm": f"#{first['id']}"}, headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["deleted"] == first["id"] and body["folder_removed"] is True
    assert body["findings_removed"] > 0 and body["reports_updated"] == [second["id"]]

    assert c.get(url).status_code == 404 and not d1.exists()
    with store.conn() as conn:  # cascade removed every row of the deleted scan, nothing else
        for table in ("findings", "scanner_runs", "scan_logs"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table} WHERE scan_id=?", (first["id"],)).fetchone()[0] == 0
    assert len(store.findings(second["id"])) == n_second and len(store.logs(second["id"])) == logs_second
    assert d2.is_dir() and (d2 / "report.html").is_file()
    assert not (d2 / "comparison.json").exists()  # its baseline is gone -> stale comparison removed
    assert store.triage_decisions()[fp].status == "confirmed"  # analyst verdicts are kept
    assert c.delete(url, json={"confirm": first["id"]}, headers=h).status_code == 404
    assert f"Scan #{first['id']} was deleted" in c.get(f"/scans?deleted={first['id']}").data.decode()


def test_delete_regenerates_comparison_against_new_baseline(cfg, fake_docker):
    app, c, token = _client(cfg)
    a, b, d = _start(c, token, "a"), _start(c, token, "b"), _start(c, token, "c")
    h = {"X-CSRF-Token": token}
    assert c.delete(f"/api/scans/{b['id']}", json={"confirm": b["id"]}, headers=h).get_json()["reports_updated"] == [d["id"]]
    comp = json.loads((Path(cfg["general"]["data_dir"]) / "scans" / f"{d['id']:04d}" / "comparison.json").read_text())
    assert comp["baseline_scan"] == a["id"]  # c is now compared with a


def test_running_scan_cannot_be_deleted(cfg, fake_docker):
    _, c, token = _client(cfg)
    h = {"X-CSRF-Token": token}
    fake_docker.clear()
    sid = c.post("/api/scans", json={"target": "juice-shop", "scanners": ["semgrep"]}, headers=h).get_json()["scan_id"]
    r = c.delete(f"/api/scans/{sid}", json={"confirm": sid}, headers=h)
    assert r.status_code == 409
    fake_docker.set()
    assert _wait(c, sid)["status"] == "completed"
    assert c.delete(f"/api/scans/{sid}", json={"confirm": sid}, headers=h).status_code == 200


def test_delete_never_removes_foreign_folders(cfg, tmp_path):
    from smartvuln.orchestrator import delete_scan
    store = Store(cfg["general"]["database"])
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "keep.txt").write_text("do not delete")
    sid = store.create_scan("juice-shop", "http://juice-shop:3000", "", "tampered", scan_dir=str(outside))
    store.finish_scan(sid, "completed", {})
    r = delete_scan(cfg, sid)
    assert r["folder_removed"] is False and (outside / "keep.txt").is_file()
    assert store.get_scan(sid) is None


# ------------------------------------------------------------------------------ numbering
def _new(store, label=""):
    sid = store.create_scan("juice-shop", "http://juice-shop:3000", "", label, number_label=True)
    store.finish_scan(sid, "completed", {})
    return sid


def test_numbers_come_from_existing_records(cfg):
    store = Store(cfg["general"]["database"])
    assert store.next_scan_id() == 1
    assert [_new(store), _new(store)] == [1, 2]
    assert store.next_scan_id() == 3                 # #1 and #2 exist -> #3
    assert _new(store) == 3
    store.delete_scan(3)
    assert _new(store) == 3                          # delete #3 while #1-#2 exist -> #3 again
    for sid in (1, 2, 3):
        store.delete_scan(sid)
    assert store.next_scan_id() == 1 and _new(store) == 1   # delete all -> #1
    _new(store)                                      # #2
    _new(store)                                      # #3
    store.delete_scan(2)                             # gap in the middle
    assert _new(store) == 4                          # numbers stay chronological for Compare
    ids = [s["id"] for s in store.list_scans(100)]
    assert len(ids) == len(set(ids))


def test_empty_name_matches_saved_number(cfg):
    store = Store(cfg["general"]["database"])
    sid = _new(store)
    assert store.get_scan(sid)["label"] == f"Scan #{sid}"
    assert store.get_scan(_new(store, "Scan #1 - Before Fixes"))["label"] == "Scan #1 - Before Fixes"


def test_concurrent_creation_never_duplicates(cfg):
    store = Store(cfg["general"]["database"])
    out, errors = [], []

    def worker():
        try:
            out.append(Store(cfg["general"]["database"]).create_scan("juice-shop", "u", "", ""))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and sorted(out) == list(range(1, 21))


def test_number_reused_through_api_and_ui(cfg, fake_docker):
    _, c, token = _client(cfg)
    h = {"X-CSRF-Token": token}
    first = _start(c, token)
    assert (first["id"], first["label"]) == (1, "Scan #1")
    assert c.delete("/api/scans/1", json={"confirm": 1}, headers=h).status_code == 200
    again = _start(c, token)
    assert (again["id"], again["label"]) == (1, "Scan #1")          # all deleted -> #1 again
    assert '"juice-shop": 2' in c.get("/scan").data.decode()        # suggestion = real next number
    assert "#1" in c.get("/scans").data.decode()


def test_reused_number_never_mixes_old_files(cfg, fake_docker):
    leftover = Path(cfg["general"]["data_dir"]) / "scans" / "0001"
    (leftover / "raw").mkdir(parents=True)
    (leftover / "raw" / "old-report.json").write_text("{}")
    _, c, token = _client(cfg)
    s = _start(c, token)
    assert s["id"] == 1 and not (leftover / "raw" / "old-report.json").exists()
    moved = list((Path(cfg["general"]["data_dir"]) / "scans" / "_replaced").glob("0001-*/raw/old-report.json"))
    assert len(moved) == 1                                           # moved aside, not deleted


# ------------------------------------------------------------------------------ projects (upload / folder)
def _zip_bytes(files):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_add_project_requires_csrf_and_valid_input(cfg):
    import io
    _, c, token = _client(cfg)
    data = {"mode": "upload", "name": "x", "file": (io.BytesIO(_zip_bytes({"a.js": "1"})), "a.zip")}
    assert c.post("/api/projects", data=data, content_type="multipart/form-data").status_code == 400
    r = c.post("/api/projects", data={"mode": "upload", "name": "x"}, headers={"X-CSRF-Token": token},
               content_type="multipart/form-data")
    assert r.status_code == 400 and "Choose" in r.get_json()["error"]
    r = c.post("/api/projects", data={"mode": "folder", "name": "x", "path": "Z:/nope/missing"},
               headers={"X-CSRF-Token": token}, content_type="multipart/form-data")
    assert r.status_code == 400 and "not found" in r.get_json()["error"].lower()
    bad = {"mode": "upload", "name": "evil", "file": (io.BytesIO(_zip_bytes({"../x.js": "1"})), "e.zip")}
    r = c.post("/api/projects", data=bad, headers={"X-CSRF-Token": token}, content_type="multipart/form-data")
    assert r.status_code == 400 and "Unsafe" in r.get_json()["error"]
    assert c.get("/api/projects").get_json() == []


def test_uploaded_project_scan_and_compare(cfg, fake_docker):
    import io
    _, c, token = _client(cfg)
    h = {"X-CSRF-Token": token}

    def upload(version):
        files = {"shop/server.js": f"// v{version}\nimport express from 'express'\napp.get('/x', h)\n"}
        r = c.post("/api/projects", data={"mode": "upload", "name": "My Shop",
                                          "file": (io.BytesIO(_zip_bytes(files)), "shop.zip")},
                   headers=h, content_type="multipart/form-data")
        assert r.status_code == 201, r.get_json()
        return r.get_json()["target_id"]

    pid = upload(1)
    assert pid == "p-my-shop"
    pre = c.get(f"/api/targets?target={pid}").get_json()
    assert pre["target"]["kind"] == "upload" and pre["target"]["has_url"] is False
    assert pre["scanners"]["zap"]["ready"] is False and "no app URL" in pre["scanners"]["zap"]["notes"][0]
    assert pre["scanners"]["semgrep"]["ready"] is True
    assert any(t["id"] == pid and t["kind"] == "upload" for t in pre["targets"])

    r = c.post("/api/scans", json={"target": pid, "scanners": ["semgrep", "trivy"], "label": "Before"}, headers=h)
    before = _wait(c, r.get_json()["scan_id"])
    assert before["status"] == "completed" and before["application"] == pid
    assert {x["scanner"]: x["status"] for x in before["runs"]} == {"semgrep": "success", "trivy": "success"}

    upload(2)  # new version of the same project
    r = c.post("/api/scans", json={"target": pid, "scanners": ["semgrep", "trivy"], "label": "After"}, headers=h)
    after = _wait(c, r.get_json()["scan_id"])
    assert after["source_ref"] != before["source_ref"]          # code changed between the scans
    page = c.get(f"/compare?baseline={before['id']}&current={after['id']}").data.decode()
    assert "different targets" not in page and "Resolved" in page
    assert "My Shop" in c.get("/scans").data.decode()           # history shows the project name

    # ZAP ticked without an app URL: skipped with a clear reason, Semgrep still runs
    r = c.post("/api/scans", json={"target": pid, "scanners": ["semgrep", "zap"]}, headers=h)
    s = _wait(c, r.get_json()["scan_id"])
    runs = {x["scanner"]: x for x in s["runs"]}
    assert runs["zap"]["status"] == "skipped" and "no running URL" in runs["zap"]["error"]
    assert runs["semgrep"]["status"] == "success"


def test_scan_center_shows_upload_folder_saved(cfg):
    _, c, _ = _client(cfg)
    page = c.get("/scan").data.decode()
    for text in ("Upload", "Folder on this PC", "Saved", "Drop your project here", "Add project", "App URL"):
        assert text in page
