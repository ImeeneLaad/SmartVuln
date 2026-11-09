"""Configuration loading: TOML file + SMARTVULN_<SECTION>_<KEY> environment overrides."""

from __future__ import annotations

import copy
import json
import os
import tomllib
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "smartvuln.toml"


def _coerce(raw: str, current: Any) -> Any:
    if isinstance(current, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    if isinstance(current, list):
        raw = raw.strip()
        return json.loads(raw) if raw.startswith("[") else [x.strip() for x in raw.split(",") if x.strip()]
    return raw


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg_path = Path(path or os.environ.get("SMARTVULN_CONFIG", DEFAULT_CONFIG))
    with open(cfg_path, "rb") as fh:
        cfg = tomllib.load(fh)
    for section, values in cfg.items():
        if not isinstance(values, dict):
            continue
        for key, current in values.items():
            env = os.environ.get(f"SMARTVULN_{section}_{key}".upper())
            if env is not None and not isinstance(current, dict):
                values[key] = _coerce(env, current)
    return cfg


# [targets.<id>] key -> (section, key) of the effective configuration
TARGET_KEYS = {
    "display_name": ("general", "display_name"),
    "url": ("target", "url"),
    "healthcheck_url": ("target", "healthcheck_url"),
    "browse_url": ("target", "browse_url"),
    "healthcheck_timeout_s": ("target", "healthcheck_timeout_s"),
    "reports_source_hash": ("target", "reports_source_hash"),
    "source_path": ("source", "path"),
    "entrypoint": ("source", "entrypoint"),
    "image": ("source", "image"),
    "semgrep_configs": ("semgrep", "configs"),
    "semgrep_exclude": ("semgrep", "exclude"),
    "trivy_skip_dirs": ("trivy", "skip_dirs"),
    "seed_paths": ("zap", "seed_paths"),
    "seed_posts": ("zap", "seed_posts"),
}


def default_target(cfg: dict[str, Any]) -> str:
    return cfg["general"]["application"]


def configured_target_ids(cfg: dict[str, Any]) -> list[str]:
    """Targets defined in smartvuln.toml (default target first)."""
    return [default_target(cfg)] + [t for t in cfg.get("targets", {}) if t != default_target(cfg)]


def target_ids(cfg: dict[str, Any]) -> list[str]:
    """Configured targets followed by projects added from the Scan Center (upload / folder)."""
    from .projects import list_projects
    return configured_target_ids(cfg) + [p["id"] for p in list_projects(cfg)]


def cfg_for_target(cfg: dict[str, Any], target_id: str | None) -> dict[str, Any]:
    """Effective configuration for one target: the base config with that target's overrides.

    The allow-list (target.allowed_hosts) and scanner settings are never widened by a target block.
    """
    if not target_id or target_id == default_target(cfg):
        return cfg
    overrides = cfg.get("targets", {}).get(target_id)
    if overrides is None:
        from .projects import get_project, project_overrides
        project = get_project(cfg, target_id)
        if project:
            return project_overrides(cfg, project)
        raise ValueError(f"unknown target '{target_id}' (known: {', '.join(target_ids(cfg))})")
    out = copy.deepcopy(cfg)
    out["general"]["application"] = target_id
    out["general"]["display_name"] = target_id
    for key, value in overrides.items():
        if key not in TARGET_KEYS:
            raise ValueError(f"[targets.{target_id}] unsupported key '{key}'")
        section, name = TARGET_KEYS[key]
        out.setdefault(section, {})[name] = value
    return out


def resolve(path: str | Path) -> Path:
    """Resolve a config path relative to the project root."""
    p = Path(path)
    return p if p.is_absolute() else PROJECT_ROOT / p
