"""False-positive assessment / triage.

Automatic triage only ever produces two states:
* ``needs_verification`` - default for every finding;
* ``likely_duplicate``   - non-primary member of a correlation group.

``confirmed`` and ``false_positive`` are *analyst decisions*: they require a
written justification and are stored per finding fingerprint, so they persist
across successive scans of the same code / endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Finding, TriageStatus

MANUAL_STATES = {TriageStatus.CONFIRMED.value, TriageStatus.FALSE_POSITIVE.value, TriageStatus.NEEDS_VERIFICATION.value}


@dataclass
class TriageDecision:
    fingerprint: str
    status: str
    note: str
    analyst: str
    updated_at: str = ""

    def validate(self) -> None:
        if self.status not in MANUAL_STATES:
            raise ValueError(f"Invalid manual triage status '{self.status}'")
        if self.status in (TriageStatus.CONFIRMED.value, TriageStatus.FALSE_POSITIVE.value):
            if len(self.note.strip()) < 10:
                raise ValueError("A justification (>= 10 characters) describing the manual verification is required.")
            if not self.analyst.strip():
                raise ValueError("Analyst name is required for a manual verdict.")


def apply_decisions(findings: list[Finding], decisions: dict[str, TriageDecision]) -> int:
    """Overlay stored analyst decisions. Returns the number of findings affected."""
    applied = 0
    for f in findings:
        d = decisions.get(f.fingerprint)
        if not d:
            continue
        f.triage_status = d.status
        f.triage_reason = f"Manual verdict by {d.analyst} ({d.updated_at}): {d.note}"
        applied += 1
    return applied
