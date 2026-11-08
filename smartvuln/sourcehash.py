"""Content hash of an application's source tree.

Used (1) as the ``source_ref`` of scans of a folder that is not a git checkout, so
History/Compare show whether the scanned code changed, and (2) to detect a stale
container: the LabShop app computes the *same* hash at start-up
(lab/labshop/lib/sourcehash.js) and reports it on /health.

Algorithm (must stay identical to the JavaScript implementation):
files with an extension in EXTENSIONS, skipping EXCLUDED_DIRS, sorted by their
POSIX relative path; sha256 over ``<relpath>\\n<file bytes>`` for each; first 12 hex.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

EXTENSIONS = (".js", ".mjs", ".html", ".css", ".json")
EXCLUDED_DIRS = {"node_modules", ".git"}


def source_hash(root: str | Path) -> str | None:
    root = Path(root)
    if not root.is_dir():
        return None
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for name in filenames:
            if name.endswith(EXTENSIONS):
                files.append(Path(dirpath, name).relative_to(root).as_posix())
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(rel.encode() + b"\n")
        h.update((root / rel).read_bytes())
    return h.hexdigest()[:12]
