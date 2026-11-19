"""Shared helpers for attack modules."""

from __future__ import annotations

import threading
from typing import Any

from ..verify.engine import Capsule, build_evidence


class FindingFactory:
    """Sequential finding ids, stable within a run."""

    def __init__(self, prefix: str = "F") -> None:
        self.prefix = prefix
        self._n = 0
        self._lock = threading.Lock()

    def next_id(self) -> str:
        with self._lock:
            self._n += 1
            return f"{self.prefix}-{self._n:03d}"


def make_finding(
    *,
    factory: FindingFactory,
    title: str,
    vuln_class: str,
    method: str,
    endpoint: str,
    capsule: Capsule,
    severity: Any,
    owner: str,
    owasp: str,
    cwe: str,
    impact: str,
    remediation: str,
    extracted: dict[str, Any] | None = None,
    retest: dict[str, Any] | None = None,
    notes: list[str] | None = None,
):
    """Assemble a Finding from a capsule + a severity result. Evidence is always redacted."""
    from ..model import Finding

    fid = factory.next_id()
    capsule.finding_id = fid
    capsule.title = title
    evidence = build_evidence(capsule, extracted=extracted)
    finding = Finding(
        id=fid,
        title=title,
        vuln_class=vuln_class,
        endpoint=endpoint,
        method=method,
        severity=severity.severity,
        cvss=severity.score,
        business_impact=severity.rationale,
        confidence="proven",
        owner=owner,
        owasp=owasp,
        cwe=cwe,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        retest=retest or {},
        proof_hash=capsule_signature(capsule),
        notes=list(notes or []),
    )
    finding.capsule = capsule  # type: ignore[attr-defined]  persisted by the report writer
    finding.retest.setdefault("capsule_steps", len(capsule.steps))
    finding.retest.setdefault("expected", capsule.expected)
    finding.retest.setdefault("reproduce", capsule.curl_hint())
    return finding


def capsule_signature(capsule: Capsule) -> str:
    import hashlib
    import json

    payload = json.dumps(capsule.to_dict(), sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
