"""User projects: safe upload extraction, folders, validation and target resolution."""

import io
import stat
import zipfile
from pathlib import Path

import pytest

from smartvuln.config import cfg_for_target, load_config, target_ids
from smartvuln.projects import (ProjectError, create_from_folder, create_from_upload, get_project, list_projects,
                                zap_url)


@pytest.fixture
def cfg(tmp_path):
    c = load_config()
    c["general"]["database"] = str(tmp_path / "t.db")
    c["general"]["data_dir"] = str(tmp_path / "data")
    return c


def _zip(entries: dict[str, str], symlink: str | None = None) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    buf.seek(0)
    return buf


APP = {"myapp/server.js": "import express from 'express'\nconst app = express()\napp.get('/x', h)\n",
       "myapp/package.json": "{}"}


def test_upload_zip_uses_single_top_folder(cfg):
    p = create_from_upload(cfg, "My App", "myapp.zip", _zip(APP))
    assert p["id"] == "p-my-app" and p["kind"] == "upload" and p["files"] == 2
    src = Path(p["source_path"])
    assert src.name == "myapp" and (src / "server.js").is_file()
    assert p["entrypoint"] == "server.js"  # Express entry detected for the route mapper
    assert get_project(cfg, "p-my-app")["name"] == "My App"


@pytest.mark.parametrize("bad", ["../evil.txt", "a/../../evil.txt", "/etc/evil", "C:/evil.txt"])
def test_zip_slip_is_rejected(cfg, bad, tmp_path):
    with pytest.raises(ProjectError, match="Unsafe path"):
        create_from_upload(cfg, "bad", "bad.zip", _zip({"ok.txt": "x", bad: "pwned"}))
    assert not (tmp_path / "evil.txt").exists() and not (Path(cfg["general"]["data_dir"]) / "evil.txt").exists()
    assert get_project(cfg, "p-bad") is None  # nothing half-created


def test_symlinks_are_skipped(cfg):
    p = create_from_upload(cfg, "links", "l.zip", _zip({"app/a.js": "x"}, symlink="app/link"))
    assert not (Path(p["source_path"]) / "link").exists()


def test_single_file_and_empty_upload(cfg):
    p = create_from_upload(cfg, "one file", "server.js", io.BytesIO(b"const x = 1"))
    assert (Path(p["source_path"]) / "server.js").is_file() and p["files"] == 1
    with pytest.raises(ProjectError, match="empty"):
        create_from_upload(cfg, "empty", "a.js", io.BytesIO(b""))


def test_reupload_same_name_replaces_code(cfg):
    first = create_from_upload(cfg, "app", "v1.zip", _zip({"app/old.js": "1"}))
    second = create_from_upload(cfg, "app", "v2.zip", _zip({"app/new.js": "2"}))
    assert first["id"] == second["id"] and first["created_at"] == second["created_at"]
    src = Path(second["source_path"])
    assert (src / "new.js").is_file() and not (src / "old.js").exists()
    assert len(list_projects(cfg)) == 1


def test_folder_project_validation(cfg, tmp_path):
    folder = tmp_path / "code"
    folder.mkdir()
    (folder / "app.py").write_text("print(1)")
    p = create_from_folder(cfg, "Local code", str(folder))
    assert p["kind"] == "folder" and Path(p["source_path"]) == folder.resolve()
    with pytest.raises(ProjectError, match="not found"):
        create_from_folder(cfg, "x", str(tmp_path / "missing"))
    with pytest.raises(ProjectError, match="full path"):
        create_from_folder(cfg, "x", "relative/path")
    with pytest.raises(ProjectError, match="name"):
        create_from_folder(cfg, "   ", str(folder))


def test_only_local_app_urls(cfg):
    p = create_from_upload(cfg, "web", "w.zip", _zip(APP), url="http://localhost:8080/")
    assert p["url"] == "http://localhost:8080"
    with pytest.raises(ProjectError, match="not allowed"):
        create_from_upload(cfg, "ext", "e.zip", _zip(APP), url="https://example.com")
    with pytest.raises(ProjectError, match="look like"):
        create_from_upload(cfg, "ext2", "e.zip", _zip(APP), url="ftp://localhost")
    with pytest.raises(ProjectError, match="image"):
        create_from_upload(cfg, "img", "e.zip", _zip(APP), image="bad image name!")


def test_zap_reaches_host_apps_through_docker_host_name():
    assert zap_url("http://localhost:8080/app") == "http://host.docker.internal:8080/app"
    assert zap_url("http://127.0.0.1:3000") == "http://host.docker.internal:3000"
    assert zap_url("http://labshop:3000") == "http://labshop:3000"
    assert zap_url("") == ""


def test_projects_are_targets(cfg):
    p = create_from_upload(cfg, "Shop", "s.zip", _zip(APP), url="http://localhost:9000", image="shop:1")
    assert target_ids(cfg)[-1] == p["id"] and "labshop" in target_ids(cfg)
    c = cfg_for_target(cfg, p["id"])
    assert c["general"]["application"] == p["id"] and c["general"]["display_name"] == "Shop"
    assert c["source"]["path"] == p["source_path"] and c["source"]["image"] == "shop:1"
    assert c["target"]["url"] == "http://host.docker.internal:9000" and c["target"]["healthcheck_url"] == "http://localhost:9000"
    assert "p/default" in c["semgrep"]["configs"]                     # any language
    assert c["target"]["allowed_hosts"] == cfg["target"]["allowed_hosts"]  # never widened
    with pytest.raises(ValueError):
        cfg_for_target(cfg, "p-does-not-exist")
    assert get_project(cfg, "../p-x") is None and get_project(cfg, "labshop") is None
