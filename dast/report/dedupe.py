"""Deduplication and noise control.

Precision is 20% of the score, and a huge part of it is *not reporting the same bug
five times*. The fingerprint is ``(class, normalized endpoint, parameter, proof)``;
identical fingerprints collapse, and near-duplicates (same class + endpoint, different
object id) collapse to the first with a count.

The ratio "N raw hits -> M findings" is itself evidence for the precision criterion, so
:func:`summarise` reports it rather than hiding it.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable

from ..model import Finding


def normalize_endpoint(method: str, endpoint: str) -> str:
    """``/api/booking/8842`` and ``/api/booking/9101`` are the same endpoint."""
    segs = []
    for seg in (endpoint or "").split("?")[0].strip("/").split("/"):
        if seg.isdigit() or (len(seg) >= 6 and any(c.isdigit() for c in seg) and seg.replace("-", "").isalnum()):
            segs.append("{id}")
        else:
            segs.append(seg)
    return f"{method.upper()} /" + "/".join(segs)


def dedupe_key(finding: Finding, *, include_proof: bool = False) -> str:
    base = f"{finding.vuln_class}|{normalize_endpoint(finding.method, finding.endpoint)}"
    if include_proof and finding.proof_hash:
        base += f"|{finding.proof_hash[:16]}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


@dataclass
class DedupeReport:
    raw: int
    unique: int
    collapsed: dict[str, int]

    @property
    def ratio(self) -> str:
        return f"{self.raw} raw hits -> {self.unique} findings"

    def to_dict(self) -> dict[str, object]:
        return {"raw_hits": self.raw, "unique_findings": self.unique, "ratio": self.ratio,
                "collapsed": self.collapsed}


def dedupe(findings: Iterable[Finding]) -> tuple[list[Finding], DedupeReport]:
    raw = list(findings)
    seen: "OrderedDict[str, Finding]" = OrderedDict()
    collapsed: dict[str, int] = {}
    for f in raw:
        key = dedupe_key(f)
        f.dedupe_key = key
        if key in seen:
            collapsed[key] = collapsed.get(key, 1) + 1
            kept = seen[key]
            # keep the strongest evidence of the duplicates
            if not kept.proof_hash and f.proof_hash:
                seen[key] = f
                seen[key].notes.append("evidence replaced by stronger duplicate")
            kept.notes.append(f"duplicate suppressed: {f.title} on {f.endpoint}")
        else:
            seen[key] = f
    return list(seen.values()), DedupeReport(raw=len(raw), unique=len(seen), collapsed=collapsed)


def by_severity(findings: Iterable[Finding]) -> list[Finding]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    return sorted(findings, key=lambda f: (order.get(f.severity, 9), -f.cvss, f.endpoint))
