"""Express route mapper - SmartVuln's custom Python analysis for SAST<->DAST correlation.

DAST findings carry URLs, SAST findings carry file paths: there is no shared key.
This module statically parses an Express entry point (``server.ts``) to build a
table *HTTP endpoint -> handler source file*:

    import { login } from './routes/login'          ->  login      => routes/login.ts
    import * as verify from './routes/verify'       ->  verify.*   => routes/verify.ts
    app.post('/rest/user/login', login())           ->  POST /rest/user/login => routes/login.ts

The correlation engine then links a ZAP alert on ``/rest/user/login`` with a
Semgrep finding in ``routes/login.ts`` **only if** both describe the same
vulnerability class.

Limitations (documented on purpose): only single-line ``app.<verb>(...)``
registrations with string / string-array paths are understood; routers mounted
from other files, dynamically built paths and the finale-rest auto-generated
``/api/*`` resources are not mapped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

_IMPORT_NAMED = re.compile(r"import\s*\{([^}]+)\}\s*from\s*['\"](\.{1,2}/[^'\"]+)['\"]")
_IMPORT_NS = re.compile(r"import\s+\*\s+as\s+(\w+)\s+from\s*['\"](\.{1,2}/[^'\"]+)['\"]")
_IMPORT_DEFAULT = re.compile(r"import\s+(\w+)\s+from\s*['\"](\.{1,2}/[^'\"]+)['\"]")
_ROUTE = re.compile(r"\bapp\.(get|post|put|patch|delete|use|all)\(\s*(\[[^\]]*\]|'[^']*'|\"[^\"]*\")\s*,(.*)$")
_STR = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_IDENT = re.compile(r"\b([A-Za-z_]\w*)(?:\.(\w+))?\s*\(?")


@dataclass(frozen=True)
class Route:
    method: str          # GET/POST/... or USE (any method, prefix match)
    path: str            # express path pattern
    handler_file: str    # repository-relative source file
    handler: str         # identifier used in server.ts
    line: int

    def matches(self, method: str, url_path: str) -> bool:
        if self.method not in ("USE", "ALL") and self.method != method.upper():
            return False
        rx = _express_to_regex(self.path, prefix=self.method == "USE")
        return rx.match(url_path) is not None


def _express_to_regex(pattern: str, prefix: bool) -> re.Pattern[str]:
    # ":param" -> one path segment; keep the (rare) inline regex groups as written.
    body = re.sub(r":(\w+)", r"[^/]+", pattern.rstrip("/") or "/")
    body = body.replace("*", ".*")
    tail = r"(?:/.*)?$" if prefix else r"/?$"
    try:
        return re.compile("^" + body + tail)
    except re.error:
        return re.compile("^" + re.escape(pattern) + tail)


def _resolve_module(spec: str, base_dir: Path, root: Path) -> str | None:
    candidate = (base_dir / spec)
    for ext in ("", ".ts", ".js", "/index.ts", "/index.js"):
        p = Path(str(candidate) + ext)
        if p.is_file():
            return p.resolve().relative_to(root.resolve()).as_posix()
    return None


def build_route_map(source_root: str | Path, entrypoint: str = "server.ts") -> list[Route]:
    root = Path(source_root)
    entry = root / entrypoint
    if not entry.is_file():
        return []
    text = entry.read_text(encoding="utf-8", errors="replace")
    symbols: dict[str, str] = {}
    for names, spec in _IMPORT_NAMED.findall(text):
        mod = _resolve_module(spec, entry.parent, root)
        if mod:
            for n in names.split(","):
                n = n.strip().split(" as ")[-1].strip()
                if n:
                    symbols[n] = mod
    for rx in (_IMPORT_NS, _IMPORT_DEFAULT):
        for name, spec in rx.findall(text):
            mod = _resolve_module(spec, entry.parent, root)
            if mod:
                symbols[name] = mod

    routes: list[Route] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = _ROUTE.search(line)
        if not m:
            continue
        method, path_arg, rest = m.group(1).upper(), m.group(2), m.group(3)
        paths = [a or b for a, b in _STR.findall(path_arg)]
        rest = rest.split("//")[0]  # drop trailing comment
        for ident, attr in _IDENT.findall(rest):
            mod = symbols.get(ident)
            if not mod or not mod.startswith("routes/"):
                continue
            handler = f"{ident}.{attr}" if attr else ident
            for p in paths:
                routes.append(Route(method, p, mod, handler, lineno))
    return routes


def handlers_for_url(routes: list[Route], method: str | None, url: str | None) -> set[str]:
    """Return handler source files that may serve ``method url``."""
    if not url or not routes:
        return set()
    path = urlparse(url).path or "/"
    path = path.rstrip("/") or "/"
    # Prefer verb-specific routes; fall back to app.use() prefixes only if none match.
    exact = {r.handler_file for r in routes if r.method not in ("USE", "ALL") and r.matches(method or "GET", path)}
    if exact:
        return exact
    return {r.handler_file for r in routes if r.method in ("USE", "ALL") and r.matches(method or "GET", path)}
