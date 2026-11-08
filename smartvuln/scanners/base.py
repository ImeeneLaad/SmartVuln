"""Common machinery for scanner adapters.

Every adapter runs its tool in a Docker container, captures stdout/stderr,
enforces a timeout, keeps the raw report on disk and returns a
:class:`~smartvuln.models.ScannerRun` whatever happens. A non-zero exit code
never discards a report: the status is derived from whether a parseable
report was produced, not from the exit code alone.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..engine.normalize import mask_secret
from ..models import ExecStatus, ScannerRun

log = logging.getLogger(__name__)
TAIL = 4000


@dataclass
class CommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    error: str = ""


def tail(text: str, n: int = TAIL) -> str:
    """Last ``n`` characters, with token-like strings masked so secrets never reach logs/DB."""
    return mask_secret(text[-n:] if text else "")


LineCallback = Callable[[str, str], None]  # (stream name "stdout"/"stderr", line)


def run_command(cmd: list[str], timeout_s: float, container_name: str | None = None,
                cwd: str | Path | None = None, on_line: LineCallback | None = None) -> CommandResult:
    """Run ``cmd``, streaming each output line to ``on_line`` while it runs.

    The full stdout/stderr is still returned. On timeout the process is killed and,
    because killing the docker CLI does not stop the container, the named container
    is removed as well.
    """
    start = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                encoding="utf-8", errors="replace", cwd=cwd, bufsize=1)
    except FileNotFoundError as exc:
        return CommandResult(None, "", "", time.monotonic() - start, error=f"executable not found: {exc}")

    out: list[str] = []
    err: list[str] = []

    def pump(stream, sink: list[str], name: str) -> None:
        for line in iter(stream.readline, ""):
            sink.append(line)
            if on_line:
                for part in line.replace("\r", "\n").split("\n"):  # progress bars use \r
                    if part.strip():
                        try:
                            on_line(name, part.rstrip())
                        except Exception:  # a logging problem must never break a scan
                            log.debug("on_line callback failed", exc_info=True)
        stream.close()

    readers = [threading.Thread(target=pump, args=(proc.stdout, out, "stdout"), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, err, "stderr"), daemon=True)]
    for t in readers:
        t.start()
    timed_out = False
    try:
        code: int | None = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out, code = True, None
        if container_name:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        proc.kill()
        proc.wait()
    for t in readers:
        t.join(timeout=10)
    return CommandResult(code, "".join(out), "".join(err), time.monotonic() - start, timed_out,
                         f"timed out after {timeout_s:.0f}s" if timed_out else "")


def docker_available() -> tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "docker CLI not found in PATH"
    res = run_command(["docker", "version", "--format", "{{.Server.Version}}"], 30)
    if res.exit_code != 0:
        return False, f"docker daemon not reachable: {tail(res.stderr, 300).strip()}"
    return True, res.stdout.strip()


def bind(source: Path, target: str, readonly: bool = False) -> list[str]:
    spec = f"type=bind,source={Path(source).resolve()},target={target}"
    return ["--mount", spec + (",readonly" if readonly else "")]


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


@dataclass
class Job:
    """One container invocation producing one JSON report."""

    label: str
    cmd: list[str]
    report: Path
    container: str


class ScannerAdapter(ABC):
    name: str = ""
    scan_type: str = ""

    def __init__(self, cfg: dict[str, Any], app_cfg: dict[str, Any], out_dir: Path,
                 on_log: Callable[[str], None] | None = None):
        self.cfg = cfg                 # this scanner's config section
        self.app_cfg = app_cfg         # whole configuration
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.on_log = on_log           # receives progress messages and the tool's own output lines

    def emit(self, message: str) -> None:
        log.info("[%s] %s", self.name, message)
        if self.on_log:
            try:
                self.on_log(mask_secret(message))
            except Exception:
                log.debug("on_log callback failed", exc_info=True)

    def container_name(self, suffix: str = "") -> str:
        return f"smartvuln-{self.name}{('-' + suffix) if suffix else ''}-{uuid.uuid4().hex[:8]}"

    @abstractmethod
    def jobs(self) -> list[Job]: ...

    def tool_errors(self, report: dict[str, Any]) -> list[str]:
        """Errors the tool reported *inside* an otherwise valid report."""
        return []

    def tool_version(self, report: dict[str, Any]) -> str:
        return ""

    def precheck(self) -> str | None:
        """Return a reason to skip, or None."""
        return None

    def run(self) -> ScannerRun:
        run = ScannerRun(scanner=self.name, scan_type=self.scan_type, status=ExecStatus.FAILED.value)
        if not self.cfg.get("enabled", True):
            run.status, run.error = ExecStatus.SKIPPED.value, "disabled in configuration"
            self.emit(f"skipped: {run.error}")
            return run
        ok, info = docker_available()
        if not ok:
            run.error = info
            self.emit(f"failed: {info}")
            return run
        self.emit(f"docker engine {info} available; running pre-checks")
        reason = self.precheck()
        if reason:
            run.status, run.error = ExecStatus.SKIPPED.value, reason
            self.emit(f"skipped: {reason}")
            return run

        statuses: list[ExecStatus] = []
        errors: list[str] = []
        outs, errs = [], []
        timeout = float(self.cfg.get("timeout_s", 1800))
        for job in self.jobs():
            job.report.unlink(missing_ok=True)
            self.emit(f"{job.label}: starting container {job.container} (timeout {timeout:.0f}s)")
            res = run_command(job.cmd, timeout, job.container,
                              on_line=(lambda stream, line: self.on_log(mask_secret(line))) if self.on_log else None)
            run.command = job.cmd if not run.command else run.command + ["&&"] + job.cmd
            run.duration_s += res.duration_s
            run.exit_code = res.exit_code if run.exit_code in (None, 0) else run.exit_code
            outs.append(f"--- {job.label} ---\n{tail(res.stdout, TAIL // 2)}")
            errs.append(f"--- {job.label} ---\n{tail(res.stderr, TAIL // 2)}")
            report = load_json(job.report)
            if report is not None:
                run.raw_report_paths.append(str(job.report))
                run.tool_version = run.tool_version or self.tool_version(report)
            if res.timed_out:
                statuses.append(ExecStatus.TIMEOUT)
                errors.append(f"{job.label}: {res.error}")
            elif report is None:
                statuses.append(ExecStatus.FAILED)
                errors.append(f"{job.label}: no parseable report (exit {res.exit_code}) {res.error}".strip())
            else:
                tool_errs = self.tool_errors(report)
                if tool_errs:
                    errors.extend(f"{job.label}: {e}" for e in tool_errs[:10])
                    statuses.append(ExecStatus.COMPLETED_WITH_ERRORS)
                else:
                    statuses.append(ExecStatus.SUCCESS)
            self.emit(f"{job.label}: {statuses[-1].value} in {res.duration_s:.0f}s (exit code {res.exit_code})"
                      + (f", report kept: {job.report.name}" if report is not None else ", no report produced"))

        run.stdout_tail = "\n".join(outs)[-TAIL:]
        run.stderr_tail = "\n".join(errs)[-TAIL:]
        run.error = mask_secret("; ".join(errors))[:2000]
        run.status = _combine(statuses).value
        return run


def _combine(statuses: list[ExecStatus]) -> ExecStatus:
    if not statuses:
        return ExecStatus.SKIPPED
    if all(s == ExecStatus.SUCCESS for s in statuses):
        return ExecStatus.SUCCESS
    if any(s.produced_report for s in statuses):
        return ExecStatus.COMPLETED_WITH_ERRORS  # partial coverage is still coverage
    if any(s == ExecStatus.TIMEOUT for s in statuses):
        return ExecStatus.TIMEOUT
    return ExecStatus.FAILED
