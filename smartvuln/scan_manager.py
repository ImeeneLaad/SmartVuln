"""Background scan execution for the web dashboard.

The Flask request that starts a scan only creates the scan record (with one
'pending' row per selected scanner) and returns its id; the real work -
``orchestrator.run_scan`` - runs in a daemon thread. Progress, per-scanner state
and execution logs are written to SQLite as they happen and polled by the UI.

Concurrency: at most one running scan per target application. The check is
done atomically in the database (``Store.create_scan(exclusive=True)``), so it
also holds against a scan started from the CLI at the same time.
"""

from __future__ import annotations

import json
import logging
import subprocess
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .config import cfg_for_target, configured_target_ids, resolve, target_ids
from .projects import create_from_folder, create_from_upload, list_projects
from .sourcehash import source_hash
from .database.store import ScanConflict, Store
from .orchestrator import ADAPTERS, _source_ref, run_scan
from .scanners.base import docker_available
from .scanners.zap import TargetNotAllowed, check_target_allowed

log = logging.getLogger(__name__)

SCANNER_INFO = {
    "semgrep": {"label": "Semgrep", "type": "SAST", "what": "static analysis of the application source code"},
    "trivy": {"label": "Trivy", "type": "SCA", "what": "dependency CVEs of the deployed image + secrets/misconfig in source"},
    "zap": {"label": "OWASP ZAP", "type": "DAST", "what": "crawl + passive + targeted active scan of the running application"},
}
STATUS_LABELS = {
    "pending": "Pending", "running": "Running", "success": "Completed",
    "completed_with_errors": "Completed (tool errors)", "failed": "Failed", "timeout": "Failed (timeout)",
    "skipped": "Skipped",
}


def probe_url(url: str, timeout: float = 3.0) -> dict[str, Any]:
    """Single availability probe (no retry loop - the ZAP adapter does the patient wait)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - configured local URL
            out: dict[str, Any] = {"reachable": 200 <= resp.status < 400, "detail": f"HTTP {resp.status}"}
            if "json" in resp.headers.get("Content-Type", ""):
                try:
                    out["json"] = json.loads(resp.read(65536))
                except ValueError:
                    pass
            return out
    except urllib.error.HTTPError as exc:
        return {"reachable": False, "detail": f"HTTP {exc.code}"}
    except (urllib.error.URLError, OSError) as exc:
        return {"reachable": False, "detail": str(getattr(exc, "reason", exc))}


def image_present(image: str) -> bool:
    try:
        return subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class ScanManager:
    def __init__(self, cfg: dict[str, Any], store: Store):
        self.cfg = cfg
        self.store = store
        self._threads: dict[int, threading.Thread] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ targets
    def targets(self) -> list[dict[str, Any]]:
        """All scan targets: configured ones (default first), then projects added in the Scan Center."""
        out = []
        projects = {p["id"]: p for p in list_projects(self.cfg)}
        for tid in target_ids(self.cfg):
            c = cfg_for_target(self.cfg, tid)
            g, t, s = c["general"], c["target"], c["source"]
            p = projects.get(tid)
            out.append({"id": tid, "name": g.get("display_name", tid), "url": t["url"],
                        "healthcheck_url": t["healthcheck_url"], "browse_url": t.get("browse_url", ""),
                        "source_path": s["path"],
                        "image": s.get("image", ""), "allowed_hosts": t.get("allowed_hosts", []),
                        "reports_source_hash": bool(t.get("reports_source_hash")),
                        "kind": p["kind"] if p else "configured",
                        "detail": (p.get("upload_name") or p["source_path"]) if p else "",
                        "files": p.get("files") if p else None})
        return out

    # ------------------------------------------------------------------ projects
    def add_upload(self, name: str, filename: str, stream, url: str = "", image: str = "") -> dict[str, Any]:
        with self._lock:
            return create_from_upload(self.cfg, name, filename, stream, url, image, set(configured_target_ids(self.cfg)))

    def add_folder(self, name: str, path: str, url: str = "", image: str = "") -> dict[str, Any]:
        with self._lock:
            return create_from_folder(self.cfg, name, path, url, image, set(configured_target_ids(self.cfg)))

    def target(self, target_id: str | None) -> dict[str, Any]:
        targets = self.targets()
        if not target_id:
            return targets[0]
        for t in targets:
            if t["id"] == target_id:
                return t
        raise ValueError(f"unknown target '{target_id}'")

    def preflight(self, target_id: str | None = None) -> dict[str, Any]:
        target = self.target(target_id)
        cfg = cfg_for_target(self.cfg, target["id"])
        src = resolve(target["source_path"])
        images = {name: cfg.get(name, {}).get("image", "") for name in ADAPTERS}
        has_url = bool(target["url"])  # uploaded/folder projects may have no running app (SAST + SCA only)
        with ThreadPoolExecutor(max_workers=6) as pool:
            f_docker = pool.submit(docker_available)
            f_probe = pool.submit(probe_url, target["healthcheck_url"]) if has_url else None
            f_images = {n: pool.submit(image_present, img) for n, img in images.items() if img}
            f_target_img = pool.submit(image_present, target["image"]) if target["image"] else None
            docker_ok, docker_info = f_docker.result()
            probe = f_probe.result() if f_probe else {"reachable": False, "detail": "no app URL"}
            present = {n: f.result() for n, f in f_images.items()} if docker_ok else {n: False for n in f_images}
            target_img = f_target_img.result() if (f_target_img and docker_ok) else False
        try:
            if has_url:
                check_target_allowed(target["url"], target["allowed_hosts"])
            allowed, allowed_msg = True, "target host is in the local allow-list"
        except TargetNotAllowed as exc:
            allowed, allowed_msg = False, str(exc)
        source_ok = src.is_dir()
        running = self.store.running_scan(target["id"])
        build = None  # does the running container match the source on disk?
        if target["reports_source_hash"] and probe["reachable"] and source_ok:
            disk = source_hash(src)
            served = probe.get("json", {}).get("source_hash")
            build = {"disk": disk, "running": served, "current": bool(served) and served == disk}
        scanners = {}
        for name, info in SCANNER_INFO.items():
            ready, notes = docker_ok, []
            if not present.get(name):
                notes.append(f"image {images[name]} not pulled yet - first run downloads it")
            if name == "semgrep" and not source_ok:
                ready = False
                notes.append("source checkout missing (scripts/fetch_target.sh)")
            if name == "zap":
                if not has_url:
                    ready = False
                    notes.append("no app URL - ZAP needs the address where the app is running")
                elif not allowed:
                    ready = False
                    notes.append(allowed_msg)
                elif not probe["reachable"]:
                    ready = False
                    notes.append(f"target not reachable ({probe['detail']}) - start it: docker compose up -d {target['id']}")
            if name in ("zap", "trivy") and build and not build["current"]:
                notes.append(f"running build is older than the source on disk - rebuild: "
                             f"docker compose up -d --build {target['id']}")
            scanners[name] = {**info, "enabled": self.cfg.get(name, {}).get("enabled", True), "ready": ready,
                              "image": images[name], "notes": notes}
        return {
            "target": {**target, "source_ref": _source_ref(src) if source_ok else "", "source_present": source_ok,
                       "reachable": probe["reachable"], "probe": probe["detail"], "allowed": allowed,
                       "image_present": target_img, "build": build, "has_url": has_url},
            "targets": [{"id": t["id"], "name": t["name"], "kind": t["kind"]} for t in self.targets()],
            "docker": {"available": docker_ok, "detail": docker_info},
            "scanners": scanners,
            "running_scan": {"id": running["id"], "started_at": running["started_at"]} if running else None,
        }

    # ------------------------------------------------------------------ execution
    def start(self, target_id: str, scanners: list[str], label: str = "") -> int:
        if target_id not in {t["id"] for t in self.targets()}:
            raise ValueError(f"unknown target '{target_id}'")
        scanners = [s for s in ADAPTERS if s in set(scanners)]  # canonical order, drop unknown/duplicates
        if not scanners:
            raise ValueError("select at least one scanner")
        cfg = cfg_for_target(self.cfg, target_id)
        with self._lock:
            src = resolve(cfg["source"]["path"])
            # An empty name becomes "Scan #<number>", with the number assigned in the same transaction.
            scan_id = self.store.create_scan(target_id, cfg["target"]["url"], _source_ref(src),
                                             label.strip(), scanners=scanners, exclusive=True, number_label=True)
            self.store.add_pending_runs(scan_id, [(s, ADAPTERS[s].scan_type) for s in scanners])
            self.store.add_log(scan_id, "smartvuln", f"scan #{scan_id} of {target_id} queued from the dashboard: "
                                                     f"{', '.join(scanners)}")
            thread = threading.Thread(target=self._worker, args=(cfg, scan_id, scanners, label),
                                      name=f"smartvuln-scan-{scan_id}", daemon=True)
            self._threads[scan_id] = thread
            thread.start()
        return scan_id

    def _worker(self, cfg: dict[str, Any], scan_id: int, scanners: list[str], label: str) -> None:
        try:
            run_scan(cfg, scanners, label, allow_external=False, scan_id=scan_id)
        except Exception as exc:  # keep the record consistent whatever happens
            log.exception("scan #%s aborted", scan_id)
            self.store.add_log(scan_id, "smartvuln", f"scan aborted by an internal error: {exc}")
            with self.store.conn() as c:
                c.execute("UPDATE scanner_runs SET status='failed', error=COALESCE(error, 'scan aborted') "
                          "WHERE scan_id=? AND status IN ('pending','running')", (scan_id,))
            scan = self.store.get_scan(scan_id) or {}
            self.store.finish_scan(scan_id, "failed", scan.get("stats") or {}, error=str(exc)[:500])
        finally:
            self._threads.pop(scan_id, None)

    def next_number(self, target_id: str | None = None) -> int:
        """Number the next scan will receive - the same one shown in History ("Scan #N")."""
        return self.store.next_scan_id()

    def is_running(self, scan_id: int) -> bool:
        t = self._threads.get(scan_id)
        return bool(t and t.is_alive())


__all__ = ["ScanManager", "ScanConflict", "STATUS_LABELS", "SCANNER_INFO", "probe_url"]
