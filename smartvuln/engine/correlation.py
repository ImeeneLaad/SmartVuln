"""Deduplication and multi-scanner correlation.

Findings are linked pairwise by explicit, explainable rules. Linked findings are
merged into *groups* with a union-find structure. Grouping never deletes a
finding: every member keeps its own provenance and raw evidence, one member is
elected group primary and the others become "likely duplicates".

Link rules (a shared severity or a shared CWE alone NEVER creates a link):

R1 same-advisory     SCA <-> SCA   same CVE/GHSA id AND same package name
R2 same-code-location any file-based finding (SAST, Trivy secret/misconfig):
                     same file AND line ranges within ``line_tolerance`` AND same category
R3 endpoint-handler  DAST <-> SAST same category AND the SAST file is the Express
                     handler of the DAST URL (see :mod:`routemap`)
R4 same-endpoint     DAST <-> DAST same category, method, path and parameter but a
                     different ZAP rule (two plugins reporting one injection point)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Iterable

from ..models import SEVERITY_RANK, CorrelationStatus, Finding, ScanType, TriageStatus, _strip_query
from .routemap import Route, handlers_for_url

# Categories for which a route-handler match (R3) is meaningful: flaws that live in
# request-handling code. Header/cookie/disclosure alerts are produced by middleware.
CODE_LEVEL_CATEGORIES = {
    "sql-injection", "nosql-injection", "xss", "code-injection", "command-injection",
    "path-traversal", "open-redirect", "ssrf", "xxe", "insecure-deserialization",
    "prototype-pollution",
}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, None: 0}


@dataclass
class Link:
    a: str
    b: str
    rule: str
    reason: str


@dataclass
class CorrelationResult:
    groups: dict[str, list[Finding]] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        multi = [g for g in self.groups.values() if len({f.scanner for f in g}) > 1]
        sast_dast = [g for g in multi if {ScanType.SAST.value, ScanType.DAST.value} <= {f.scan_type for f in g}]
        return {
            "findings": sum(len(g) for g in self.groups.values()),
            "unique_issues": len(self.groups),
            "duplicates": sum(len(g) - 1 for g in self.groups.values()),
            "multi_scanner_groups": len(multi),
            "sast_dast_groups": len(sast_dast),
            "single_scanner_findings": sum(len(g) for g in self.groups.values() if len({f.scanner for f in g}) == 1),
            "uncorrelated_findings": sum(1 for g in self.groups.values() if len(g) == 1),
            "links": len(self.links),
        }


class _UnionFind:
    def __init__(self, items: Iterable[str]):
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _lines_close(a: Finding, b: Finding, tol: int) -> bool:
    if a.line_start is None or b.line_start is None:
        return a.line_start is None and b.line_start is None
    a_end = a.line_end or a.line_start
    b_end = b.line_end or b.line_start
    return a.line_start - tol <= b_end and b.line_start - tol <= a_end


def find_links(findings: list[Finding], routes: list[Route] | None = None, line_tolerance: int = 2) -> list[Link]:
    links: list[Link] = []
    sca = [f for f in findings if f.category == "vulnerable-dependency"]
    file_based = [f for f in findings if f.file_path and f.category != "vulnerable-dependency"]
    dast = [f for f in findings if f.scan_type == ScanType.DAST.value]
    sast = [f for f in findings if f.scan_type == ScanType.SAST.value]

    # R1 - bucket by (advisory id, package)
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in sca:
        for adv in set(f.cve):
            buckets[(adv, f.package_name or "")].append(f)
    seen_pairs: set[tuple[str, str]] = set()
    for (adv, pkg), members in buckets.items():
        for a, b in combinations(members, 2):
            pair = tuple(sorted((a.id, b.id)))
            if a.id != b.id and pair not in seen_pairs:
                seen_pairs.add(pair)
                links.append(Link(a.id, b.id, "R1 same-advisory",
                                  f"same advisory {adv} in package '{pkg}' ({a.package_version} / {b.package_version})"))

    # R2 - bucket by (file, category)
    by_file: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in file_based:
        by_file[(f.file_path, f.category)].append(f)
    for (path, cat), members in by_file.items():
        for a, b in combinations(members, 2):
            if a.id != b.id and _lines_close(a, b, line_tolerance):
                links.append(Link(a.id, b.id, "R2 same-code-location",
                                  f"both report '{cat}' at {path}:{a.line_start}/{b.line_start} "
                                  f"(±{line_tolerance} lines)"))

    # R3 - DAST URL resolved to handler file, matched against SAST findings in that file
    if routes:
        sast_by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in sast:
            if f.category in CODE_LEVEL_CATEGORIES:
                sast_by_file[f.file_path or ""].append(f)
        for d in dast:
            if d.category not in CODE_LEVEL_CATEGORIES:
                continue
            for handler in sorted(handlers_for_url(routes, d.http_method, d.url)):
                for s in sast_by_file.get(handler, []):
                    if s.category == d.category:
                        links.append(Link(d.id, s.id, "R3 endpoint-handler",
                                          f"DAST '{d.category}' on {d.http_method} {_strip_query(d.url)} "
                                          f"is served by {handler}, where SAST reports '{s.category}' at line {s.line_start}"))

    # R4 - two DAST rules on the same injection point
    by_point: dict[tuple, list[Finding]] = defaultdict(list)
    for d in dast:
        if d.parameter:
            by_point[(d.category, d.http_method, _strip_query(d.url), d.parameter)].append(d)
    for (cat, method, path, param), members in by_point.items():
        for a, b in combinations(members, 2):
            if a.rule_id != b.rule_id:
                links.append(Link(a.id, b.id, "R4 same-endpoint",
                                  f"'{a.rule_id}' and '{b.rule_id}' both report '{cat}' on {method} {path} param '{param}'"))
    return links


def _primary_key(f: Finding):
    return (SEVERITY_RANK.get(f.severity, 0), CONFIDENCE_RANK.get(f.confidence, 0), f.cvss_score or 0, f.id)


def correlate(findings: list[Finding], routes: list[Route] | None = None, line_tolerance: int = 2) -> CorrelationResult:
    # Exact duplicates (same fingerprint) are collapsed first - they are the same record.
    unique: dict[str, Finding] = {}
    for f in findings:
        if not f.fingerprint:
            f.compute_fingerprint()
        unique.setdefault(f.id, f)
    items = list(unique.values())

    links = find_links(items, routes, line_tolerance)
    uf = _UnionFind(f.id for f in items)
    for link in links:
        uf.union(link.a, link.b)

    reasons: dict[str, list[str]] = defaultdict(list)
    for link in links:
        reasons[link.a].append(f"{link.rule}: {link.reason}")
        reasons[link.b].append(f"{link.rule}: {link.reason}")

    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in items:
        groups[uf.find(f.id)].append(f)

    result = CorrelationResult(links=links)
    for idx, (_, members) in enumerate(sorted(groups.items(), key=lambda kv: -max(_primary_key(m) for m in kv[1])[0])):
        gid = f"G{idx + 1:04d}"
        scanners = {m.scanner for m in members}
        primary = max(members, key=_primary_key)
        if len(members) == 1:
            status = CorrelationStatus.UNCORRELATED.value
        elif len(scanners) > 1:
            status = CorrelationStatus.MULTI_SCANNER.value
        else:
            status = CorrelationStatus.SAME_SCANNER_DUPLICATE.value
        for m in members:
            m.group_id = gid
            m.correlation_status = status
            m.correlation_reasons = sorted(set(reasons.get(m.id, [])))
            m.related_ids = [o.id for o in members if o.id != m.id]
            m.is_group_primary = m is primary
            if not m.is_group_primary and m.triage_status == TriageStatus.NEEDS_VERIFICATION.value:
                m.triage_status = TriageStatus.LIKELY_DUPLICATE.value
                m.triage_reason = f"Grouped with {primary.id} ({primary.scanner}: {primary.title}); see correlation reasons."
        result.groups[gid] = members
    return result
