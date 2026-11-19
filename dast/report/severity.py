"""Business-context severity.

The pack: *"severity judged by what the endpoint means for the business, not only a
generic score"*. The research pack's evidence: commercial leaders agree with human
re-scorers only ~68% of the time, so a transparent rubric is a genuine edge.

Design note — why **additive** modifiers rather than multipliers. The obvious model is
``cvss x business_multiplier``, but the factors are correlated: an unauthenticated
cross-tenant PII read is not 2.5 x 1.8 x 1.4 = 6.3x worse than its base score, it is
capped at "critical" and the multiplication is meaningless. In practice
multiplication drives *every* business-relevant finding to 10.0 within one release,
which destroys the very ranking the report exists to provide. Additive modifiers keep
the ordering sane and the arithmetic checkable in one line:

    7.5 + 1.2 (cross_agency) + 1.5 (auth_bypass) + 0.6 (pii) = 10.8 -> capped at 10.0

Every finding prints this string, so a reviewer can argue with the number instead of
just disbelieving it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

#: tag -> (points added to the CVSS floor, why it is there)
BUSINESS_MODIFIERS: list[tuple[str, float, str]] = [
    ("cross_agency", 1.2, "crosses an agency (tenant) boundary"),
    ("auth_bypass", 1.5, "reachable without authentication"),
    ("money_movement", 1.5, "moves, creates or mis-states money"),
    ("pii", 0.6, "exposes traveller PII"),
    ("write_operation", 0.4, "mutates state"),
    ("internal_only", -1.5, "internal-only exposure, limited blast radius"),
]

SEVERITY_BANDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "informational"),
]

#: anything in this set means the finding is never reported below "high"
NEVER_LOW = {"cross_agency", "money_movement", "auth_bypass"}


@dataclass
class SeverityResult:
    severity: str
    score: float
    cvss_floor: float
    modifiers: list[tuple[str, float, str]]
    rationale: str

    @property
    def multiplier(self) -> float:  # kept for backwards compatibility of reports
        return round(self.score / self.cvss_floor, 3) if self.cvss_floor else 1.0

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "score": self.score,
            "cvss_floor": self.cvss_floor,
            "modifiers": [{"tag": t, "points": p, "why": w} for t, p, w in self.modifiers],
            "rationale": self.rationale,
        }


def band(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "informational"


def score(cvss_floor: float, factors: Iterable[str], *, cap: float = 10.0) -> SeverityResult:
    """Apply the business modifier table to a CVSS floor."""
    table = {tag: (points, why) for tag, points, why in BUSINESS_MODIFIERS}
    applied: list[tuple[str, float, str]] = []
    for tag in dict.fromkeys(factors):  # de-duplicate, preserve order
        if tag in table:
            points, why = table[tag]
            applied.append((tag, points, why))

    raw = max(cvss_floor, 0.0) + sum(p for _, p, _ in applied)
    final = round(min(max(raw, 0.0), cap), 1)
    floored = False
    if set(factors) & NEVER_LOW and final < 7.0:
        final, floored = 7.0, True

    parts = [f"CVSS floor {cvss_floor:.1f}"]
    for tag, points, _ in applied:
        parts.append(f"{'+' if points >= 0 else '-'} {abs(points):g} ({tag})")
    parts.append(f"= {raw:.1f}")
    if floored:
        parts.append("-> raised to 7.0 (money/tenant/auth findings are never below high)")
    elif raw > cap:
        parts.append(f"-> capped at {cap:.1f}")
    return SeverityResult(
        severity=band(final),
        score=final,
        cvss_floor=cvss_floor,
        modifiers=applied,
        rationale=" ".join(parts),
    )


#: CVSS-floor defaults per finding kind. Deliberately conservative: the floor is the
#: technical severity of the primitive, and business context lifts it above.
FLOORS: dict[str, float] = {
    "bola": 6.5,
    "bfla": 7.1,
    "unauthenticated_data_exposure": 7.5,
    "double_refund": 6.2,
    "refund_over_paid": 6.2,
    "skipped_payment": 6.8,
    "fare_tampering": 6.0,
    "coupon_reuse": 5.3,
    "shadow_api": 6.0,
    "zombie_api": 6.0,
    "mass_assignment": 8.2,
    "info_disclosure": 4.3,
}


def from_finding_kind(
    kind: str,
    *,
    cross_tenant: bool = False,
    unauth: bool = False,
    money: bool = False,
    pii: bool = False,
    write: bool = False,
    internal_only: bool = False,
) -> SeverityResult:
    """Map a vulnerability kind + context flags to a scored severity."""
    factors: list[str] = []
    if cross_tenant:
        factors.append("cross_agency")
    if money:
        factors.append("money_movement")
    if unauth:
        factors.append("auth_bypass")
    if pii:
        factors.append("pii")
    if write:
        factors.append("write_operation")
    if internal_only:
        factors.append("internal_only")
    return score(FLOORS.get(kind, 5.0), factors)
