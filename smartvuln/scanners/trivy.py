"""Trivy (SCA) adapter.

Two jobs:
* ``image`` - dependency CVEs of the *deployed* container image (the Juice Shop
  repository does not commit a lockfile, so the image's node_modules are the
  authoritative dependency inventory);
* ``fs``    - secrets, IaC/Dockerfile misconfigurations and any lockfiles in the source tree.
"""

from __future__ import annotations

from typing import Any

from ..config import resolve
from ..models import ScanType
from .base import Job, ScannerAdapter, bind


class TrivyAdapter(ScannerAdapter):
    name = "trivy"
    scan_type = ScanType.SCA.value

    def _base(self, container: str) -> list[str]:
        return ["docker", "run", "--rm", "--name", container,
                "--mount", f"type=volume,source={self.cfg.get('cache_volume', 'smartvuln-trivy-cache')},target=/root/.cache",
                *bind(self.out_dir, "/out")]

    def jobs(self) -> list[Job]:
        image = self.cfg.get("image", "aquasec/trivy:latest")
        sev = self.cfg.get("severities", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
        jobs: list[Job] = []
        target_image = self.app_cfg["source"].get("image")
        if self.cfg.get("scan_image", True) and target_image:
            c = self.container_name("image")
            cmd = self._base(c) + [
                "--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
                image, "image", "--scanners", "vuln", "--severity", sev, "--image-src", "docker,remote",
                "--format", "json", "--output", "/out/trivy-image.json", "--timeout", "20m", target_image]
            jobs.append(Job(f"image {target_image}", cmd, self.out_dir / "trivy-image.json", c))
        src = resolve(self.app_cfg["source"]["path"])
        if self.cfg.get("scan_source", True) and src.is_dir():
            c = self.container_name("fs")
            cmd = self._base(c) + bind(src, "/src", readonly=True) + [
                image, "fs", "--scanners", "vuln,secret,misconfig", "--severity", sev,
                *[a for d in self.cfg.get("skip_dirs", ["node_modules"]) for a in ("--skip-dirs", d)],
                "--format", "json", "--output", "/out/trivy-fs.json", "--timeout", "20m", "/src"]
            jobs.append(Job("filesystem (secrets, misconfig, lockfiles)", cmd, self.out_dir / "trivy-fs.json", c))
        return jobs

    def precheck(self) -> str | None:
        if not self.jobs():
            return "nothing to scan: no image configured and source directory missing"
        return None

    def tool_version(self, report: dict[str, Any]) -> str:
        return f"schema {report.get('SchemaVersion', '?')}"
