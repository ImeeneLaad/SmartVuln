"""OWASP ZAP (DAST) adapter using the ZAP Automation Framework.

A plan is generated per scan:
  requestor (seed endpoints an SPA spider cannot discover) -> spider ->
  passive scan -> [targeted active scan with a limited rule set] -> JSON + HTML report.

Safety: the target host must be in ``target.allowed_hosts`` unless the caller
explicitly allows external targets, and the target must pass a health check.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from ..models import ScanType
from .base import Job, ScannerAdapter, bind

# Active-scan rules enabled in the "targeted" profile (ZAP plugin ids).
# Only rules shipped in ghcr.io/zaproxy/zaproxy:stable (2.17.0); ZAP ignores unknown ids with a warning,
# which was observed for 40024 (SQLite time-based) and 40033 (NoSQL) - those live in beta/alpha add-ons.
ACTIVE_RULES = {
    40018: "SQL Injection", 40012: "Cross Site Scripting (Reflected)",
    40014: "Cross Site Scripting (Persistent)", 6: "Path Traversal", 90020: "Remote OS Command Injection",
    20019: "External Redirect", 40009: "Server Side Include", 90019: "Server Side Code Injection",
    0: "Directory Browsing",
}


class TargetNotAllowed(Exception):
    pass


def check_target_allowed(url: str, allowed_hosts: list[str], allow_external: bool = False) -> None:
    host = urlparse(url).hostname or ""
    if not allow_external and host not in allowed_hosts:
        raise TargetNotAllowed(
            f"Refusing to scan '{host}': not in target.allowed_hosts {allowed_hosts}. "
            "SmartVuln only scans the isolated local test environment by default.")


def wait_until_healthy(url: str, timeout_s: float, interval_s: float = 3.0) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - local URL from config
                if 200 <= resp.status < 400:
                    return True, f"HTTP {resp.status}"
                last = f"HTTP {resp.status}"
        except (urllib.error.URLError, OSError) as exc:
            last = str(exc)
        time.sleep(interval_s)
    return False, f"not healthy after {timeout_s:.0f}s ({last})"


def build_plan(target: str, cfg: dict[str, Any]) -> dict[str, Any]:
    target = target.rstrip("/")
    jobs: list[dict[str, Any]] = [
        {"type": "requestor", "name": "seed-endpoints",
         "requests": [{"url": target + p, "method": "GET"} for p in cfg.get("seed_paths", [])]
                     + [{"url": target + s["path"], "method": "POST", "data": s.get("body", ""),
                         "headers": [f"Content-Type: {s.get('content_type', 'application/json')}"]}
                        for s in cfg.get("seed_posts", [])]},
        {"type": "spider", "parameters": {"context": "target", "maxDuration": int(cfg.get("spider_minutes", 2))}},
        {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
    ]
    if cfg.get("profile", "targeted") == "targeted":
        jobs.append({
            "type": "activeScan",
            "parameters": {"context": "target", "maxScanDurationInMins": int(cfg.get("active_scan_minutes", 10)),
                           "maxRuleDurationInMins": 3, "threadPerHost": 4},
            "policyDefinition": {"defaultStrength": "medium", "defaultThreshold": "off",
                                 "rules": [{"id": rid, "name": n, "strength": "medium", "threshold": "medium"}
                                           for rid, n in ACTIVE_RULES.items()]},
        })
        jobs.append({"type": "passiveScan-wait", "parameters": {"maxDuration": 2}})
    jobs += [
        {"type": "report", "parameters": {"template": "traditional-json", "reportDir": "/zap/wrk",
                                          "reportFile": "zap-report.json"}},
        {"type": "report", "parameters": {"template": "traditional-html", "reportDir": "/zap/wrk",
                                          "reportFile": "zap-report.html"}},
    ]
    return {"env": {"contexts": [{"name": "target", "urls": [target], "includePaths": [target + ".*"]}],
                    "parameters": {"failOnError": False, "failOnWarning": False, "progressToStdout": True}},
            "jobs": jobs}


class ZapAdapter(ScannerAdapter):
    name = "zap"
    scan_type = ScanType.DAST.value
    allow_external = False

    def precheck(self) -> str | None:
        t = self.app_cfg["target"]
        if not t.get("url"):
            return "no running URL for this target - add the app's URL to run ZAP"
        try:
            check_target_allowed(t["url"], t.get("allowed_hosts", []), self.allow_external)
        except TargetNotAllowed as exc:
            return str(exc)
        self.emit(f"target {t['url']} is in the allow-list; checking availability at {t['healthcheck_url']}")
        ok, info = wait_until_healthy(t["healthcheck_url"], float(t.get("healthcheck_timeout_s", 180)))
        if not ok:
            return f"target health check failed: {t['healthcheck_url']} {info}"
        self.emit(f"target is healthy ({info}); profile '{self.cfg.get('profile', 'targeted')}'")
        return None

    def jobs(self) -> list[Job]:
        t = self.app_cfg["target"]
        plan = build_plan(t["url"], self.cfg)
        # The Automation Framework accepts JSON-compatible YAML, so no YAML dependency is needed.
        (self.out_dir / "zap-plan.yaml").write_text(json.dumps(plan, indent=2), encoding="utf-8")
        try:  # ZAP runs as uid 1000 inside the container; on Linux CI the folder must be writable
            os.chmod(self.out_dir, 0o777)
        except OSError:
            pass
        container = self.container_name()
        net = ["--network", t["docker_network"]] if t.get("docker_network") else []
        cmd = ["docker", "run", "--rm", "--name", container, *net, *bind(self.out_dir, "/zap/wrk"),
               self.cfg.get("image", "ghcr.io/zaproxy/zaproxy:stable"),
               "zap.sh", "-cmd", "-autorun", "/zap/wrk/zap-plan.yaml"]
        return [Job(f"automation plan ({self.cfg.get('profile', 'targeted')})", cmd,
                    self.out_dir / "zap-report.json", container)]

    def tool_version(self, report: dict[str, Any]) -> str:
        return str(report.get("@version", ""))
