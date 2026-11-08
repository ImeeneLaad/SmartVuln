"""Mapping of CWEs / rule keywords to a small set of vulnerability classes.

The class ("category") is what lets SmartVuln compare a Semgrep rule, a ZAP
plugin and a Trivy secret finding that describe the same weakness with
different vocabularies. A shared category is *necessary but never sufficient*
for correlation: the correlation engine additionally requires a location match.
"""

from __future__ import annotations

import re

# CWE number -> category. Related CWEs are grouped into one family.
CWE_FAMILY: dict[int, str] = {
    89: "sql-injection", 564: "sql-injection",
    943: "nosql-injection",
    94: "code-injection", 95: "code-injection", 96: "code-injection",
    77: "command-injection", 78: "command-injection",
    79: "xss", 80: "xss", 83: "xss", 87: "xss",
    22: "path-traversal", 23: "path-traversal", 36: "path-traversal", 73: "path-traversal",
    601: "open-redirect",
    918: "ssrf",
    611: "xxe", 776: "xxe",
    798: "hardcoded-secret", 259: "hardcoded-secret", 321: "hardcoded-secret", 522: "hardcoded-secret",
    327: "weak-crypto", 328: "weak-crypto", 326: "weak-crypto", 916: "weak-crypto", 330: "weak-crypto", 338: "weak-crypto",
    502: "insecure-deserialization",
    1321: "prototype-pollution", 915: "prototype-pollution",
    1333: "regex-dos",
    352: "csrf",
    287: "broken-auth", 345: "broken-auth", 347: "broken-auth", 384: "broken-auth", 613: "broken-auth",
    639: "access-control", 284: "access-control", 285: "access-control", 862: "access-control", 548: "information-disclosure",
    200: "information-disclosure", 209: "information-disclosure", 497: "information-disclosure",
    532: "information-disclosure", 615: "information-disclosure", 538: "information-disclosure",
    693: "missing-security-header", 1021: "missing-security-header", 319: "missing-security-header",
    614: "insecure-cookie", 1004: "insecure-cookie", 1275: "insecure-cookie",
    16: "security-misconfiguration", 942: "security-misconfiguration", 264: "security-misconfiguration",
    250: "security-misconfiguration", 269: "security-misconfiguration", 829: "security-misconfiguration",
}

# Keyword fallbacks, checked in order, when no CWE maps (rule ids / titles).
KEYWORDS: list[tuple[str, str]] = [
    (r"nosql|mongo|\$where", "nosql-injection"),
    (r"sql|sequelize", "sql-injection"),
    (r"xss|cross.site.script|innerhtml|bypasssecuritytrust", "xss"),
    (r"eval|code.injection|vm\.run|function\(", "code-injection"),
    (r"command|exec|spawn|shell", "command-injection"),
    (r"path.traversal|directory.traversal|path.join|sendfile", "path-traversal"),
    (r"redirect", "open-redirect"),
    (r"ssrf|server.side.request", "ssrf"),
    (r"xxe|xml.external", "xxe"),
    (r"secret|private.key|password|api.key|token|credential|jwt.*hardcod|hardcod", "hardcoded-secret"),
    (r"md5|sha1|weak.hash|crypto", "weak-crypto"),
    (r"deserializ", "insecure-deserialization"),
    (r"prototype", "prototype-pollution"),
    (r"redos|regular.expression", "regex-dos"),
    (r"csp|content.security.policy|x-frame|clickjack|hsts|strict-transport|x-content-type|header", "missing-security-header"),
    (r"cookie", "insecure-cookie"),
    (r"cors|cross.domain|misconfig", "security-misconfiguration"),
    (r"disclos|leak|timestamp|comment|error.message|server.version|directory.listing|private.ip", "information-disclosure"),
]

_CWE_RE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)


def parse_cwes(values) -> list[str]:
    """Normalize any CWE representation ("CWE-89: …", 89, "89") to ["CWE-89"]."""
    if values is None:
        return []
    if not isinstance(values, (list, tuple, set)):
        values = [values]
    out: list[str] = []
    for v in values:
        if v is None or v == "" or v == -1 or v == "-1" or v == 0 or v == "0":
            continue
        s = str(v)
        m = _CWE_RE.search(s)
        num = m.group(1) if m else (s if s.isdigit() else None)
        if num:
            cwe = f"CWE-{int(num)}"
            if cwe not in out:
                out.append(cwe)
    return out


def cwe_number(cwe: str) -> int | None:
    m = _CWE_RE.search(cwe or "")
    return int(m.group(1)) if m else None


def categorize(cwes: list[str], *texts: str | None) -> str:
    for c in cwes:
        n = cwe_number(c)
        if n in CWE_FAMILY:
            return CWE_FAMILY[n]
    blob = " ".join(t for t in texts if t).lower()
    for pattern, cat in KEYWORDS:
        if re.search(pattern, blob):
            return cat
    return "other"
