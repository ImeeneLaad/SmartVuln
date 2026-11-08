"""Semgrep (SAST) adapter - registry rulesets + SmartVuln custom rules."""

from __future__ import annotations

from typing import Any

from ..config import resolve
from ..models import ScanType
from .base import Job, ScannerAdapter, bind


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    scan_type = ScanType.SAST.value

    def precheck(self) -> str | None:
        src = resolve(self.app_cfg["source"]["path"])
        if not src.is_dir():
            return f"source directory {src} not found (run scripts/fetch_target.sh)"
        return None

    def jobs(self) -> list[Job]:
        src = resolve(self.app_cfg["source"]["path"])
        container = self.container_name()
        mounts = bind(src, "/src", readonly=True) + bind(self.out_dir, "/out")
        config_args: list[str] = []
        for i, c in enumerate(self.cfg.get("configs", ["p/default"])):
            if c.startswith(("p/", "r/", "http")) or c == "auto":
                config_args += ["--config", c]
            else:  # local rule file/dir -> mount read-only
                local = resolve(c)
                target = f"/rules{i}" + ("" if local.is_dir() else f"/{local.name}")
                mounts += bind(local if local.is_dir() else local.parent, f"/rules{i}", readonly=True)
                config_args += ["--config", target]
        excludes: list[str] = []
        for e in self.cfg.get("exclude", []):
            excludes += ["--exclude", e]
        report = self.out_dir / "semgrep.json"
        cmd = ["docker", "run", "--rm", "--name", container, *mounts, "-w", "/src",
               self.cfg.get("image", "semgrep/semgrep:latest"),
               "semgrep", "scan", *config_args, *excludes,
               "--json", "--output", "/out/semgrep.json", "--metrics=off",
               "--timeout", "30", "--max-target-bytes", "1000000", "."]
        return [Job("semgrep scan", cmd, report, container)]

    def tool_errors(self, report: dict[str, Any]) -> list[str]:
        # Semgrep lists per-file parse problems as errors; those of level "warn" do not
        # invalidate the scan, so only real errors degrade the status.
        out = []
        for e in report.get("errors", []) or []:
            if str(e.get("level", "error")).lower() == "error":
                out.append(f"{e.get('type', 'error')}: {str(e.get('message', ''))[:200]}")
        return out

    def tool_version(self, report: dict[str, Any]) -> str:
        return str(report.get("version", ""))
