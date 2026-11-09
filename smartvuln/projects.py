"""User projects: code uploaded from the Scan Center (zip or single file) or a folder on this PC.

A project is an additional scan target, stored as data/projects/<id>/project.json:
  - "upload": the archive is extracted into data/projects/<id>/source/ (safely: no paths
    escaping the folder, no symbolic links, size and file-count limits);
  - "folder": an existing folder is referenced in place and mounted read-only by the scanners.
Optional "url" (where the app runs, needed by OWASP ZAP; local hosts only) and "image"
(Docker image, for Trivy's image scan). Uploading again with the same name replaces the
code of that project, so its scans can be compared before/after.
"""

from __future__ import annotations

import json
import re
import shutil
import stat
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import urlparse

from .config import resolve

PREFIX = "p-"
MAX_FILES = 50_000
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024  # 1 GiB
LOCAL_HOSTS = {"localhost", "127.0.0.1"}
# Generic settings for arbitrary projects (any language).
SEMGREP_CONFIGS = ["p/default", "custom_rules/semgrep"]
SEMGREP_EXCLUDE = ["node_modules", ".git", "vendor", "venv", ".venv", "dist", "build", "target", "__pycache__",
                   "*.min.js"]
TRIVY_SKIP_DIRS = ["node_modules", ".git", "venv", ".venv", "vendor"]
ENTRYPOINTS = ["server.js", "app.js", "index.js", "server.ts", "app.ts", "index.ts", "server.mjs", "app.mjs",
               "src/server.js", "src/app.js", "src/index.js", "src/server.ts", "src/app.ts", "src/index.ts"]


class ProjectError(ValueError):
    """Invalid project input (shown to the user)."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def projects_root(cfg: dict[str, Any]) -> Path:
    return resolve(cfg["general"]["data_dir"]) / "projects"


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")[:40]
    if not slug:
        raise ProjectError("Give the project a name.")
    return PREFIX + slug


def list_projects(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    root = projects_root(cfg)
    out = []
    if root.is_dir():
        for meta in root.glob(f"{PREFIX}*/project.json"):
            try:
                out.append(json.loads(meta.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
    return sorted(out, key=lambda p: p.get("created_at", ""))


def get_project(cfg: dict[str, Any], project_id: str) -> dict[str, Any] | None:
    if not project_id.startswith(PREFIX) or "/" in project_id or "\\" in project_id:
        return None
    meta = projects_root(cfg) / project_id / "project.json"
    try:
        return json.loads(meta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def project_overrides(cfg: dict[str, Any], project: dict[str, Any]) -> dict[str, Any]:
    """Effective configuration for scanning a project (used by config.cfg_for_target)."""
    import copy
    out = copy.deepcopy(cfg)
    url = project.get("url") or ""
    out["general"]["application"] = project["id"]
    out["general"]["display_name"] = project["name"]
    out["source"].update({"path": project["source_path"], "entrypoint": project.get("entrypoint") or "server.js",
                          "image": project.get("image") or ""})
    out["target"].update({"url": zap_url(url), "healthcheck_url": url, "browse_url": url,
                          "reports_source_hash": False})
    out["semgrep"].update({"configs": SEMGREP_CONFIGS, "exclude": SEMGREP_EXCLUDE})
    out["trivy"]["skip_dirs"] = TRIVY_SKIP_DIRS
    out["zap"].update({"seed_paths": [], "seed_posts": []})
    return out


def zap_url(url: str) -> str:
    """ZAP runs in a container: 'localhost' there is the container itself, so an app running on
    this PC is reached through host.docker.internal (Docker Desktop's name for the host)."""
    if not url:
        return ""
    p = urlparse(url)
    if p.hostname in LOCAL_HOSTS:
        netloc = "host.docker.internal" + (f":{p.port}" if p.port else "")
        return p._replace(netloc=netloc).geturl()
    return url


def validate_url(cfg: dict[str, Any], url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ProjectError("The app URL must look like http://localhost:8080")
    allowed = set(cfg["target"].get("allowed_hosts", [])) | LOCAL_HOSTS
    if p.hostname not in allowed:
        raise ProjectError(f"Only local apps can be scanned ({', '.join(sorted(allowed))}); "
                           f"'{p.hostname}' is not allowed.")
    return url.rstrip("/")


def validate_image(image: str) -> str:
    image = (image or "").strip()
    if image and not re.fullmatch(r"[a-z0-9][a-z0-9._/:@-]{0,254}", image):
        raise ProjectError("The Docker image name is not valid (example: myapp:latest).")
    return image


def detect_entrypoint(source: Path) -> str:
    """Best guess of the Express entry file, for the route mapper (empty if none)."""
    for rel in ENTRYPOINTS:
        f = source / rel
        try:
            if f.is_file() and re.search(r"express|app\.(get|post|use)\(", f.read_text(encoding="utf-8", errors="ignore")):
                return rel
        except OSError:
            continue
    return ""


def _count_files(path: Path, limit: int = MAX_FILES) -> int:
    n = 0
    for p in path.rglob("*"):
        if p.is_file():
            n += 1
            if n > limit:
                break
    return n


def _safe_extract(archive: Path, dest: Path) -> None:
    """Extract a zip without letting any entry escape `dest` (zip-slip), skipping symlinks."""
    with zipfile.ZipFile(archive) as zf:
        members = zf.infolist()
        if len(members) > MAX_FILES:
            raise ProjectError(f"The archive has too many files (limit {MAX_FILES}).")
        if sum(m.file_size for m in members) > MAX_EXTRACTED_BYTES:
            raise ProjectError("The archive is too large once extracted (limit 1 GB).")
        root = dest.resolve()
        for m in members:
            name = m.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if name.startswith("/") or (parts and re.match(r"^[A-Za-z]:", parts[0])) or ".." in parts:
                raise ProjectError(f"Unsafe path in archive: {m.filename}")
            if stat.S_ISLNK(m.external_attr >> 16):
                continue  # symbolic links could point outside the project
            target = (dest / name).resolve()
            if root != target and root not in target.parents:
                raise ProjectError(f"Unsafe path in archive: {m.filename}")
            if m.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(m) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def _single_root(source: Path) -> Path:
    """If an archive contains one top-level folder only (myapp/...), scan that folder."""
    entries = [p for p in source.iterdir() if p.name not in ("__MACOSX",)]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return source


def _save(cfg: dict[str, Any], project: dict[str, Any]) -> dict[str, Any]:
    folder = projects_root(cfg) / project["id"]
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "project.json").write_text(json.dumps(project, indent=2), encoding="utf-8")
    return project


def _base(cfg: dict[str, Any], name: str, url: str, image: str, configured_ids: set[str]) -> dict[str, Any]:
    pid = slugify(name)
    if pid in configured_ids:
        raise ProjectError("This name is already used by a built-in target.")
    existing = get_project(cfg, pid) or {}
    return {"id": pid, "name": name.strip()[:80], "url": validate_url(cfg, url), "image": validate_image(image),
            "created_at": existing.get("created_at") or _now(), "updated_at": _now()}


def create_from_upload(cfg: dict[str, Any], name: str, filename: str, stream: BinaryIO, url: str = "",
                       image: str = "", configured_ids: set[str] = frozenset()) -> dict[str, Any]:
    project = _base(cfg, name, url, image, set(configured_ids))
    filename = Path(filename or "upload").name
    folder = projects_root(cfg) / project["id"]
    folder.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="extract-", dir=folder))
    try:
        upload = folder / ".upload.tmp"
        with open(upload, "wb") as out:
            shutil.copyfileobj(stream, out)
        if upload.stat().st_size == 0:
            raise ProjectError("The uploaded file is empty.")
        if zipfile.is_zipfile(upload):
            try:
                _safe_extract(upload, staging)
            except zipfile.BadZipFile as exc:
                raise ProjectError(f"The archive could not be read: {exc}") from exc
        else:  # a single source file
            shutil.copyfile(upload, staging / re.sub(r"[^\w.\-]", "_", filename))
        upload.unlink(missing_ok=True)
        if not any(staging.iterdir()):
            raise ProjectError("The archive is empty.")
        source = folder / "source"
        if source.exists():  # new version of the same project: replace its code
            shutil.rmtree(source)
        staging.rename(source)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        (folder / ".upload.tmp").unlink(missing_ok=True)
        if not (folder / "project.json").exists():
            shutil.rmtree(folder, ignore_errors=True)
        raise
    root = _single_root(source)
    project.update({"kind": "upload", "upload_name": filename, "source_path": str(root.resolve()),
                    "entrypoint": detect_entrypoint(root), "files": _count_files(root)})
    return _save(cfg, project)


def create_from_folder(cfg: dict[str, Any], name: str, path: str, url: str = "", image: str = "",
                       configured_ids: set[str] = frozenset()) -> dict[str, Any]:
    project = _base(cfg, name, url, image, set(configured_ids))
    folder = Path((path or "").strip().strip('"')).expanduser()
    if not str(folder) or not folder.is_absolute():
        raise ProjectError("Enter the full path of a folder, e.g. C:\\Users\\me\\projects\\myapp")
    if not folder.is_dir():
        raise ProjectError(f"Folder not found: {folder}")
    project.update({"kind": "folder", "source_path": str(folder.resolve()),
                    "entrypoint": detect_entrypoint(folder), "files": _count_files(folder)})
    return _save(cfg, project)
