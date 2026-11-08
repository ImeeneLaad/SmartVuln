"""SQLite persistence for scan history, scanner executions, findings and analyst triage."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..engine.triage import TriageDecision
from ..models import Finding, ScannerRun

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    application   TEXT NOT NULL,
    target_url    TEXT,
    source_ref    TEXT,
    label         TEXT,
    is_demo       INTEGER NOT NULL DEFAULT 0,   -- 1 = loaded from demonstration fixtures
    status        TEXT NOT NULL DEFAULT 'running',
    scan_dir      TEXT,
    stats_json    TEXT,
    notes         TEXT
);
CREATE TABLE IF NOT EXISTS scanner_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanner       TEXT NOT NULL,
    scan_type     TEXT NOT NULL,
    status        TEXT NOT NULL,
    exit_code     INTEGER,
    duration_s    REAL,
    tool_version  TEXT,
    error         TEXT,
    stdout_tail   TEXT,
    stderr_tail   TEXT,
    raw_reports   TEXT,
    findings_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id            TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    scanner       TEXT NOT NULL,
    scan_type     TEXT NOT NULL,
    severity      TEXT NOT NULL,
    priority      TEXT,
    risk_score    REAL,
    category      TEXT,
    title         TEXT,
    location      TEXT,
    cwe           TEXT,
    cve           TEXT,
    correlation_status TEXT,
    triage_status TEXT,
    group_id      TEXT,
    is_primary    INTEGER,
    data_json     TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
CREATE TABLE IF NOT EXISTS triage (
    fingerprint   TEXT PRIMARY KEY,
    status        TEXT NOT NULL,
    note          TEXT NOT NULL,
    analyst       TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ts            TEXT NOT NULL,
    source        TEXT NOT NULL,          -- 'smartvuln' or a scanner name
    message       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scan_logs ON scan_logs(scan_id, id);
CREATE TABLE IF NOT EXISTS triage_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL,
    status        TEXT NOT NULL,
    note          TEXT NOT NULL,
    analyst       TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# Columns added after the first release; created on existing databases at start-up.
MIGRATIONS = {
    "scans": {"scanners": "TEXT", "phase": "TEXT", "progress": "REAL DEFAULT 0", "error": "TEXT"},
    "scanner_runs": {"started_at": "TEXT", "finished_at": "TEXT"},
}
ACTIVE = ("pending", "running")


class ScanConflict(Exception):
    """A scan of the same application is already in progress."""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            c.execute("PRAGMA journal_mode=WAL")  # dashboard reads while scanner threads write
            c.executescript(SCHEMA)
            for table, cols in MIGRATIONS.items():
                have = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
                for col, decl in cols.items():
                    if col not in have:
                        c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ---------------------------------------------------------------- scans
    def create_scan(self, application: str, target_url: str | None, source_ref: str | None,
                    label: str = "", is_demo: bool = False, scan_dir: str = "", started_at: str | None = None,
                    scanners: list[str] | None = None, exclusive: bool = False, number_label: bool = False) -> int:
        """Insert a scan in state 'running' and return its number.

        The number is the highest existing scan number + 1, computed from the records in the
        table (not SQLite's AUTOINCREMENT counter), so deleted numbers at the end are reused:
        no scans -> #1; #1 and #2 -> #3; delete #3 while #1-#2 exist -> #3 again. Gaps in the
        middle are not refilled, which keeps numbers in chronological order (Compare's
        "previous scan" relies on it). Computing and inserting happen in one IMMEDIATE
        transaction, so concurrent inserts can never receive the same number.

        With ``exclusive`` the insert is refused if another scan of the same application is
        still running. With ``number_label`` an empty label becomes "Scan #<number>".
        """
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            if exclusive:
                busy = c.execute("SELECT id FROM scans WHERE application=? AND status='running'", (application,)).fetchone()
                if busy:
                    c.rollback()
                    raise ScanConflict(f"scan #{busy['id']} of '{application}' is still running")
            scan_id = int(c.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM scans").fetchone()[0])
            if number_label and not label.strip():
                label = f"Scan #{scan_id}"
            c.execute(
                "INSERT INTO scans (id, started_at, application, target_url, source_ref, label, is_demo, scan_dir, scanners, phase) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (scan_id, started_at or _now(), application, target_url, source_ref, label, int(is_demo), scan_dir,
                 ",".join(scanners or []), "queued"))
            return scan_id

    def next_scan_id(self) -> int:
        """Number the next scan will receive (see create_scan)."""
        with self.conn() as c:
            return int(c.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM scans").fetchone()[0])

    def set_phase(self, scan_id: int, phase: str, progress: float | None = None, scan_dir: str | None = None) -> None:
        with self.conn() as c:
            c.execute("UPDATE scans SET phase=?, progress=COALESCE(?, progress), scan_dir=COALESCE(?, scan_dir) WHERE id=?",
                      (phase, progress, scan_dir, scan_id))

    def finish_scan(self, scan_id: int, status: str, stats: dict[str, Any], scan_dir: str | None = None,
                    error: str | None = None) -> None:
        with self.conn() as c:
            c.execute("UPDATE scans SET finished_at=?, status=?, stats_json=?, scan_dir=COALESCE(?, scan_dir), "
                      "phase='finished', progress=1, error=COALESCE(?, error) WHERE id=?",
                      (_now(), status, json.dumps(stats), scan_dir, error, scan_id))

    def save_stats(self, scan_id: int, stats: dict[str, Any]) -> None:
        with self.conn() as c:
            c.execute("UPDATE scans SET stats_json=? WHERE id=?", (json.dumps(stats), scan_id))

    def running_scan(self, application: str | None = None) -> dict[str, Any] | None:
        q = "SELECT id FROM scans WHERE status='running'" + (" AND application=?" if application else "")
        with self.conn() as c:
            r = c.execute(q + " ORDER BY id DESC LIMIT 1", (application,) if application else ()).fetchone()
        return self.get_scan(int(r["id"])) if r else None

    def mark_interrupted(self) -> int:
        """Scans left 'running' by a previous process can never finish: mark them interrupted."""
        with self.conn() as c:
            ids = [r["id"] for r in c.execute("SELECT id FROM scans WHERE status='running'")]
            for sid in ids:
                c.execute("UPDATE scans SET status='interrupted', finished_at=?, phase='interrupted', "
                          "error='server stopped while the scan was running' WHERE id=?", (_now(), sid))
                c.execute("UPDATE scanner_runs SET status='failed', error='interrupted (server stopped)', finished_at=? "
                          "WHERE scan_id=? AND status IN ('pending','running')", (_now(), sid))
        return len(ids)

    def list_scans(self, limit: int = 100, finished_only: bool = False) -> list[dict[str, Any]]:
        where = "WHERE status IN ('completed','partial')" if finished_only else ""
        with self.conn() as c:
            rows = c.execute(f"SELECT * FROM scans {where} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["stats"] = json.loads(d.pop("stats_json") or "{}")
            d["runs"] = self.scanner_runs(d["id"])
            out.append(d)
        return out

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["stats"] = json.loads(d.pop("stats_json") or "{}")
        d["runs"] = self.scanner_runs(scan_id)
        return d

    def latest_scan_id(self, include_demo: bool = True) -> int | None:
        # failed scans (no scanner produced a report) stay in the history but are not the default view
        q = "SELECT id FROM scans WHERE status IN ('completed', 'partial')" + ("" if include_demo else " AND is_demo = 0")
        with self.conn() as c:
            r = c.execute(q + " ORDER BY id DESC LIMIT 1").fetchone()
        return int(r["id"]) if r else None

    def previous_scan_id(self, scan_id: int) -> int | None:
        scan = self.get_scan(scan_id)
        if not scan:
            return None
        with self.conn() as c:
            r = c.execute("SELECT id FROM scans WHERE id < ? AND application = ? AND is_demo = ? "
                          "AND status IN ('completed', 'partial') "
                          "ORDER BY id DESC LIMIT 1", (scan_id, scan["application"], scan["is_demo"])).fetchone()
        return int(r["id"]) if r else None

    def delete_scan(self, scan_id: int) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM scans WHERE id=?", (scan_id,))

    # ---------------------------------------------------------------- scanner runs
    def add_pending_runs(self, scan_id: int, scanners: list[tuple[str, str]]) -> None:
        with self.conn() as c:
            c.executemany("INSERT INTO scanner_runs (scan_id, scanner, scan_type, status) VALUES (?,?,?,'pending')",
                          [(scan_id, name, stype) for name, stype in scanners])

    def mark_run_started(self, scan_id: int, scanner: str) -> None:
        with self.conn() as c:
            c.execute("UPDATE scanner_runs SET status='running', started_at=? WHERE scan_id=? AND scanner=?",
                      (_now(), scan_id, scanner))

    def add_scanner_run(self, scan_id: int, run: ScannerRun) -> None:
        """Store the final outcome of a scanner (updates its pending/running row if present)."""
        values = (run.scan_type, run.status, run.exit_code, round(run.duration_s, 1), run.tool_version, run.error,
                  run.stdout_tail, run.stderr_tail, json.dumps(run.raw_report_paths), run.findings_count)
        with self.conn() as c:
            cur = c.execute(
                "UPDATE scanner_runs SET scan_type=?, status=?, exit_code=?, duration_s=?, tool_version=?, error=?, "
                "stdout_tail=?, stderr_tail=?, raw_reports=?, findings_count=?, finished_at=?, "
                "started_at=COALESCE(started_at, ?) WHERE scan_id=? AND scanner=?",
                (*values, _now(), _now(), scan_id, run.scanner))
            if cur.rowcount == 0:
                c.execute(
                    "INSERT INTO scanner_runs (scan_type, status, exit_code, duration_s, tool_version, error, stdout_tail, "
                    "stderr_tail, raw_reports, findings_count, finished_at, scan_id, scanner) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (*values, _now(), scan_id, run.scanner))

    def set_findings_count(self, scan_id: int, scanner: str, count: int) -> None:
        with self.conn() as c:
            c.execute("UPDATE scanner_runs SET findings_count=? WHERE scan_id=? AND scanner=?", (count, scan_id, scanner))

    # ---------------------------------------------------------------- execution logs
    def add_log(self, scan_id: int, source: str, message: str) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO scan_logs (scan_id, ts, source, message) VALUES (?,?,?,?)",
                      (scan_id, _now(), source, message[:2000]))

    def logs(self, scan_id: int, after_id: int = 0, limit: int = 500, source: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT id, ts, source, message FROM scan_logs WHERE scan_id=? AND id>?"
        args: list[Any] = [scan_id, after_id]
        if source:
            q += " AND source=?"
            args.append(source)
        with self.conn() as c:
            rows = c.execute(q + " ORDER BY id LIMIT ?", (*args, limit)).fetchall()
        return [dict(r) for r in rows]

    def log_count(self, scan_id: int) -> int:
        with self.conn() as c:
            return int(c.execute("SELECT COUNT(*) AS n FROM scan_logs WHERE scan_id=?", (scan_id,)).fetchone()["n"])

    def scanner_runs(self, scan_id: int) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM scanner_runs WHERE scan_id=? ORDER BY scanner", (scan_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["raw_reports"] = json.loads(d["raw_reports"] or "[]")
            out.append(d)
        return out

    def run_statuses(self, scan_id: int) -> dict[str, str]:
        return {r["scanner"]: r["status"] for r in self.scanner_runs(scan_id)}

    # ---------------------------------------------------------------- findings
    def save_findings(self, scan_id: int, findings: list[Finding]) -> None:
        rows = [(scan_id, f.id, f.fingerprint, f.scanner, f.scan_type, f.severity, f.priority, f.risk_score,
                 f.category, f.title, f.location, ",".join(f.cwe), ",".join(f.cve), f.correlation_status,
                 f.triage_status, f.group_id, int(f.is_group_primary), json.dumps(f.to_dict()))
                for f in findings]
        with self.conn() as c:
            c.executemany("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def replace_findings(self, scan_id: int, findings: list[Finding]) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        self.save_findings(scan_id, findings)

    def findings(self, scan_id: int) -> list[Finding]:
        with self.conn() as c:
            rows = c.execute("SELECT data_json FROM findings WHERE scan_id=? ORDER BY risk_score DESC", (scan_id,)).fetchall()
        fs = [Finding.from_dict(json.loads(r["data_json"])) for r in rows]
        decisions = self.triage_decisions()
        for f in fs:  # manual verdicts made after the scan still apply
            d = decisions.get(f.fingerprint)
            if d:
                f.triage_status = d.status
                f.triage_reason = f"Manual verdict by {d.analyst} ({d.updated_at}): {d.note}"
                if d.status == "false_positive":
                    f.risk_score, f.priority = 0.0, "P4"
        return fs

    def finding(self, scan_id: int, finding_id: str) -> Finding | None:
        return next((f for f in self.findings(scan_id) if f.id == finding_id), None)

    def finding_history(self, fingerprint: str) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute("SELECT f.scan_id, f.severity, f.risk_score, s.started_at FROM findings f "
                             "JOIN scans s ON s.id = f.scan_id WHERE f.fingerprint=? ORDER BY f.scan_id",
                             (fingerprint,)).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- triage
    def set_triage(self, decision: TriageDecision) -> None:
        decision.validate()
        decision.updated_at = decision.updated_at or _now()
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO triage VALUES (?,?,?,?,?)",
                      (decision.fingerprint, decision.status, decision.note, decision.analyst, decision.updated_at))
            c.execute("INSERT INTO triage_log (fingerprint, status, note, analyst, created_at) VALUES (?,?,?,?,?)",
                      (decision.fingerprint, decision.status, decision.note, decision.analyst, decision.updated_at))

    def triage_decisions(self) -> dict[str, TriageDecision]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM triage WHERE status != 'needs_verification'").fetchall()
        return {r["fingerprint"]: TriageDecision(r["fingerprint"], r["status"], r["note"], r["analyst"], r["updated_at"])
                for r in rows}

    def triage_log(self, fingerprint: str) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM triage_log WHERE fingerprint=? ORDER BY id DESC", (fingerprint,)).fetchall()
        return [dict(r) for r in rows]
