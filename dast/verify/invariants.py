"""Business-logic invariants.

The pack: *"the most damaging ones are often business-logic flaws"*, and conventional
scanners miss them. The trick that makes them mechanically verifiable: model the flow
as a state machine, state the invariants as code, then a violated invariant *is* the
proof. There is no judgement call and therefore no false positive.

    Σ refunds ≤ Σ payments          money cannot be created
    count(refunds) ≤ 1              a booking cannot be refunded twice
    CONFIRMED ⇒ paid > 0            the payment step cannot be skipped
    final ≥ quoted                  a client cannot lower its own fare
    pax ≥ 1                         negative quantities are not a discount
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

EPSILON = 0.01  # currency rounding tolerance


@dataclass
class Ledger:
    booking_id: str
    status: str = ""
    quoted: float = 0.0
    final: float = 0.0
    pax: int = 1
    payments: list[dict[str, Any]] = field(default_factory=list)
    refunds: list[dict[str, Any]] = field(default_factory=list)

    @property
    def paid(self) -> float:
        return round(sum(float(p.get("amount", 0)) for p in self.payments), 2)

    @property
    def refunded(self) -> float:
        return round(sum(float(r.get("amount", 0)) for r in self.refunds), 2)

    @property
    def successful_refunds(self) -> int:
        return sum(1 for r in self.refunds if str(r.get("status", "ok")).lower() in ("ok", "success", "settled"))

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "Ledger":
        return cls(
            booking_id=str(payload.get("bookingId") or payload.get("id") or ""),
            status=str(payload.get("status") or ""),
            quoted=float(payload.get("quotedAmount") or payload.get("quoted_amount") or 0),
            final=float(payload.get("finalAmount") or payload.get("final_amount") or 0),
            pax=int(payload.get("paxCount") or payload.get("pax") or 1),
            payments=list(payload.get("payments") or []),
            refunds=list(payload.get("refunds") or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bookingId": self.booking_id,
            "status": self.status,
            "quotedAmount": self.quoted,
            "finalAmount": self.final,
            "paxCount": self.pax,
            "paid": self.paid,
            "refunded": self.refunded,
            "paymentCount": len(self.payments),
            "refundCount": len(self.refunds),
            "successfulRefunds": self.successful_refunds,
        }

    def summary_line(self) -> str:
        return (
            f"booking {self.booking_id}: status={self.status} quoted={self.quoted:.2f} "
            f"final={self.final:.2f} paid={self.paid:.2f} refunded={self.refunded:.2f} "
            f"refunds={len(self.refunds)}"
        )


@dataclass
class Invariant:
    name: str
    description: str
    check: Callable[[Ledger], bool]
    proof: str

    def violated(self, ledger: Ledger) -> bool:
        try:
            return not self.check(ledger)
        except Exception:  # noqa: BLE001 - a crashing invariant is not a finding
            return False


INVARIANTS: list[Invariant] = [
    Invariant(
        name="refund_le_paid",
        description="total refunded must not exceed total paid",
        check=lambda l: l.refunded <= l.paid + EPSILON,
        proof="refunded {refunded:.2f} > paid {paid:.2f}: the endpoint created money",
    ),
    Invariant(
        name="single_refund",
        description="a booking may be refunded at most once",
        check=lambda l: l.successful_refunds <= 1,
        proof="successful_refunds={successful_refunds}: refunds were paid more than once",
    ),
    Invariant(
        name="paid_before_confirm",
        description="a booking may not reach CONFIRMED without payment",
        check=lambda l: l.status.upper() != "CONFIRMED" or l.paid > EPSILON,
        proof="status=CONFIRMED with paid={paid:.2f}: the payment step was skipped",
    ),
    Invariant(
        name="monotonic_amount",
        description="the final amount may not fall below the server-quoted amount",
        check=lambda l: l.final + EPSILON >= l.quoted,
        proof="final={final:.2f} < quoted={quoted:.2f}: a client-supplied value overrode the fare",
    ),
    Invariant(
        name="no_negative_pax",
        description="passenger count must be at least one",
        check=lambda l: l.pax >= 1,
        proof="pax={pax}: a negative or zero quantity was accepted",
    ),
    Invariant(
        name="refund_requires_terminal_state",
        description="refunds only make sense once a booking is cancelled or already refunded",
        check=lambda l: not l.refunds or l.status.upper() in ("CANCELLED", "REFUNDED", "CANCELED"),
        proof="refunds={refundCount} while status={status}: refund issued from a live booking",
    ),
]

BY_NAME: dict[str, Invariant] = {i.name: i for i in INVARIANTS}


@dataclass
class InvariantResult:
    name: str
    description: str
    passed: bool
    detail: str
    ledger: Ledger

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant": self.name,
            "description": self.description,
            "passed": self.passed,
            "detail": self.detail,
            "ledger": self.ledger.to_dict(),
        }


def _detail(inv: Invariant, ledger: Ledger) -> str:
    try:
        return inv.proof.format(
            refunded=ledger.refunded,
            paid=ledger.paid,
            final=ledger.final,
            quoted=ledger.quoted,
            pax=ledger.pax,
            status=ledger.status,
            successful_refunds=ledger.successful_refunds,
            refundCount=len(ledger.refunds),
        )
    except (KeyError, IndexError, ValueError):
        return inv.description


def check_all(ledger: Ledger, *, only: Iterable[str] | None = None) -> list[InvariantResult]:
    wanted = set(only) if only else None
    results: list[InvariantResult] = []
    for inv in INVARIANTS:
        if wanted and inv.name not in wanted:
            continue
        passed = not inv.violated(ledger)
        results.append(
            InvariantResult(
                name=inv.name,
                description=inv.description,
                passed=passed,
                detail="" if passed else _detail(inv, ledger),
                ledger=ledger,
            )
        )
    return results


def violations(ledger: Ledger, *, only: Iterable[str] | None = None) -> list[InvariantResult]:
    return [r for r in check_all(ledger, only=only) if not r.passed]
