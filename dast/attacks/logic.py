"""Business-logic attacks, verified by ledger invariants.

Each attack drives a real flow on a **synthetic booking created for the purpose**, then
reads the ledger back and checks invariants. The invariant check is the verifier, so a
finding here is arithmetic, not opinion — which is exactly why logic bugs are the place
to beat conventional scanners on precision as well as depth.

Write operations are gated (:mod:`dast.gate`); reads are not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..errors import ApprovalDenied, ScopeViolation, TransportError, STOPPING
from ..gate import ApprovalGate
from ..http import Client, Response
from ..model import classify_data
from ..report.severity import from_finding_kind
from ..verify.engine import Capsule, excerpt
from ..verify.invariants import Ledger, violations
from .common import FindingFactory, make_finding


@dataclass
class FlowPaths:
    """Endpoint map for the booking flow. Override per target; defaults suit the mock."""

    hold: str = "/api/hold"
    pay: str = "/api/pay"
    confirm: str = "/api/confirm"
    cancel: str = "/api/cancel"
    refund: str = "/api/refund"
    rebook: str = "/api/rebook"
    ledger: str = "/api/ledger/{id}"

    def ledger_for(self, booking_id: str) -> str:
        return self.ledger.replace("{id}", booking_id)


@dataclass
class LogicContext:
    client: Client
    gate: ApprovalGate
    factory: FindingFactory
    role: str
    owner: str = "unassigned"
    paths: FlowPaths = field(default_factory=FlowPaths)
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------------------


def _call(ctx: LogicContext, method: str, path: str, *, body: Any = None, note: str = "") -> Response:
    return ctx.client.request(
        method, path, role=ctx.role, json=body, component="logic", note=note
    )


def _ledger(ctx: LogicContext, booking_id: str) -> Ledger | None:
    try:
        resp = _call(ctx, "GET", ctx.paths.ledger_for(booking_id), note=f"ledger:{booking_id}")
    except STOPPING:
        raise
    except (ScopeViolation, TransportError) as exc:
        ctx.notes.append(f"ledger read failed for {booking_id}: {exc}")
        return None
    if resp.status != 200:
        ctx.notes.append(f"ledger read for {booking_id} returned {resp.status}")
        return None
    try:
        return Ledger.from_api(resp.json())
    except ValueError:
        ctx.notes.append(f"ledger for {booking_id} was not JSON")
        return None


def _open_booking(ctx: LogicContext, *, amount: float, pax: int = 1) -> tuple[str, Response] | None:
    try:
        resp = _call(ctx, "POST", ctx.paths.hold, body={"pax": pax, "amount": amount}, note="synthetic-booking")
    except STOPPING:
        raise
    except (ScopeViolation, TransportError) as exc:
        ctx.notes.append(f"could not create a synthetic booking: {exc}")
        return None
    if resp.status >= 400:
        ctx.notes.append(f"hold returned {resp.status}")
        return None
    try:
        bid = str(resp.json().get("bookingId"))
    except (ValueError, AttributeError):
        ctx.notes.append("hold response had no bookingId")
        return None
    return bid, resp


def _require_write(ctx: LogicContext, action: str, detail: str) -> bool:
    try:
        ctx.gate.require(action=action, risk="write operation on a synthetic test booking", detail=detail)
        return True
    except ApprovalDenied as exc:
        ctx.notes.append(f"skipped: {exc}")
        return False


def _base_capsule(ctx: LogicContext, title: str, method: str, endpoint: str) -> Capsule:
    cap = Capsule(finding_id="", title=title, endpoint=endpoint, method=method)
    cap.expected = {"status": 200}
    return cap


# --------------------------------------------------------------------------------------
# 1. double refund
# --------------------------------------------------------------------------------------


def test_double_refund(ctx: LogicContext, *, amount: float = 1000.0) -> Any | None:
    """cancel -> refund -> refund. Invariant: at most one successful refund."""
    if not _require_write(
        ctx,
        "Create a synthetic booking, pay it, cancel it, then request two refunds",
        f"amount {amount:.2f} on booking created solely for this test",
    ):
        return None

    opened = _open_booking(ctx, amount=amount)
    if not opened:
        return None
    bid, hold_resp = opened

    try:
        pay = _call(ctx, "POST", ctx.paths.pay, body={"booking": bid, "amount": amount}, note="pay")
        cancel = _call(ctx, "POST", ctx.paths.cancel, body={"booking": bid}, note="cancel")
        first = _call(ctx, "POST", ctx.paths.refund, body={"booking": bid, "amount": amount}, note="refund-1")
        second = _call(ctx, "POST", ctx.paths.refund, body={"booking": bid, "amount": amount}, note="refund-2")
    except (ScopeViolation, TransportError) as exc:
        ctx.notes.append(f"double-refund flow aborted: {exc}")
        return None

    ledger = _ledger(ctx, bid)
    if ledger is None:
        return None
    broken = violations(ledger, only=["single_refund", "refund_le_paid"])
    if not broken:
        ctx.notes.append(f"double refund on {bid}: invariants held; not a finding")
        return None

    cap = _base_capsule(ctx, "Double refund", "POST", ctx.paths.refund)
    for label, resp in (("hold", hold_resp), ("pay", pay), ("cancel", cancel),
                        ("refund_1", first), ("refund_2", second)):
        cap.add(label, resp, role=ctx.role)
    cap.add("ledger", _call(ctx, "GET", ctx.paths.ledger_for(bid), note="ledger-proof"), role=ctx.role)

    severity = from_finding_kind("double_refund", money=True, write=True)
    first_line, _ = excerpt(second, max_lines=2)
    impact = (
        f"`POST {ctx.paths.refund}` accepts a second refund for a booking that is already refunded. "
        f"On booking {bid} ({ledger.summary_line()}), the ledger shows "
        f"{ledger.successful_refunds} successful refunds totalling {ledger.refunded:.2f} against "
        f"{ledger.paid:.2f} paid. Each replay of the same request moves money again: "
        f"{next((r.detail for r in broken), '')}. "
        f"Nothing in the request changes between calls, so this is replayable at will."
    )
    remediation = (
        "Make refund issuance idempotent and state-guarded in one transaction: lock the booking row, "
        "reject when `refunds.any(status == 'settled')`, and require a client-supplied idempotency key. "
        "Enforce the ledger invariant `Σrefunds ≤ Σpayments` in the database as a constraint so a "
        "future handler cannot regress it. Last response: " + first_line.replace("\n", " ")[:200]
    )

    finding = make_finding(
        factory=ctx.factory,
        title=f"Double refund — booking {bid} was refunded twice",
        vuln_class="double_refund",
        method="POST",
        endpoint=ctx.paths.refund,
        capsule=cap,
        severity=severity,
        owner=ctx.owner,
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        cwe="CWE-837 Improper Enforcement of a Single, Unique Action",
        impact=impact,
        remediation=remediation,
        extracted={
            "booking_id": bid,
            "ledger": ledger.to_dict(),
            "violated_invariants": [r.to_dict() for r in broken],
            "request_count": 5,
        },
        retest={"mode": "re-execute", "test_id": "logic_double_refund", "role": ctx.role},
        notes=ctx.notes,
    )
    return finding


# --------------------------------------------------------------------------------------
# 2. skipped payment
# --------------------------------------------------------------------------------------


def test_skipped_payment(ctx: LogicContext, *, amount: float = 750.0) -> Any | None:
    """hold -> confirm. Invariant: a confirmed booking has paid > 0."""
    if not _require_write(
        ctx,
        "Create a synthetic booking and confirm it without paying",
        f"amount {amount:.2f} never paid; asserts the booking still reaches CONFIRMED",
    ):
        return None

    opened = _open_booking(ctx, amount=amount)
    if not opened:
        return None
    bid, hold_resp = opened

    try:
        confirm = _call(ctx, "POST", ctx.paths.confirm, body={"booking": bid}, note="confirm-without-payment")
    except (ScopeViolation, TransportError) as exc:
        ctx.notes.append(f"skipped-payment flow aborted: {exc}")
        return None

    ledger = _ledger(ctx, bid)
    if ledger is None:
        return None
    broken = violations(ledger, only=["paid_before_confirm"])
    if not broken:
        ctx.notes.append(f"skipped payment on {bid}: invariant held; not a finding")
        return None

    cap = _base_capsule(ctx, "Skipped payment step", "POST", ctx.paths.confirm)
    cap.add("hold", hold_resp, role=ctx.role)
    cap.add("confirm_without_payment", confirm, role=ctx.role)
    cap.add("ledger", _call(ctx, "GET", ctx.paths.ledger_for(bid), note="ledger-proof"), role=ctx.role)

    severity = from_finding_kind("skipped_payment", money=True, write=True)
    impact = (
        f"`POST {ctx.paths.confirm}` moves a booking to CONFIRMED with no payment recorded. "
        f"Booking {bid}: status={ledger.status}, paid={ledger.paid:.2f}, quoted={ledger.quoted:.2f}. "
        f"The state machine permits the transition HELD -> CONFIRMED, skipping PAY, so a caller that "
        f"never calls `{ctx.paths.pay}` still gets a confirmed, ticketed booking — an unpaid "
        f"reservation that suppliers will honour. "
        f"{next((r.detail for r in broken), '')}"
    )
    remediation = (
        f"Encode the flow as an explicit state machine and reject illegal transitions: CONFIRMED may only "
        f"be entered from PAID. Validate server-side that `payments.total >= quoted_amount` inside the "
        f"confirm transaction, and return 409 for an out-of-order transition. Add a regression test for "
        f"the HELD -> CONFIRMED edge."
    )

    return make_finding(
        factory=ctx.factory,
        title=f"Skipped payment — booking {bid} confirmed with {ledger.paid:.2f} paid",
        vuln_class="skipped_payment",
        method="POST",
        endpoint=ctx.paths.confirm,
        capsule=cap,
        severity=severity,
        owner=ctx.owner,
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        cwe="CWE-841 Improper Enforcement of Behavioral Workflow",
        impact=impact,
        remediation=remediation,
        extracted={
            "booking_id": bid,
            "ledger": ledger.to_dict(),
            "violated_invariants": [r.to_dict() for r in broken],
        },
        retest={"mode": "re-execute", "test_id": "logic_skipped_payment", "role": ctx.role},
        notes=ctx.notes,
    )


# --------------------------------------------------------------------------------------
# 3. fare tampering
# --------------------------------------------------------------------------------------


def test_fare_tampering(ctx: LogicContext, *, quoted: float = 5000.0, tampered: float = 100.0) -> Any | None:
    """hold at X -> rebook with a client-supplied lower amount. Invariant: final >= quoted."""
    if not _require_write(
        ctx,
        "Create a synthetic booking, then rebook it with a client-supplied lower fare",
        f"quoted {quoted:.2f}, client sends {tampered:.2f}",
    ):
        return None

    opened = _open_booking(ctx, amount=quoted)
    if not opened:
        return None
    bid, hold_resp = opened

    try:
        rebook = _call(
            ctx, "POST", ctx.paths.rebook, body={"booking": bid, "amount": tampered}, note="fare-tamper"
        )
    except (ScopeViolation, TransportError) as exc:
        ctx.notes.append(f"fare-tamper flow aborted: {exc}")
        return None

    ledger = _ledger(ctx, bid)
    if ledger is None:
        return None
    broken = violations(ledger, only=["monotonic_amount"])
    if not broken:
        ctx.notes.append(f"fare tampering on {bid}: server ignored the client amount; not a finding")
        return None

    cap = _base_capsule(ctx, "Fare tampering", "POST", ctx.paths.rebook)
    cap.add("hold", hold_resp, role=ctx.role)
    cap.add("rebook_with_client_amount", rebook, role=ctx.role)
    cap.add("ledger", _call(ctx, "GET", ctx.paths.ledger_for(bid), note="ledger-proof"), role=ctx.role)

    severity = from_finding_kind("fare_tampering", money=True, write=True)
    impact = (
        f"`POST {ctx.paths.rebook}` writes the client-supplied `amount` straight into the booking's "
        f"final amount. Booking {bid} was quoted {ledger.quoted:.2f} and rebooked at "
        f"{ledger.final:.2f}, a {100 * (1 - ledger.final / ledger.quoted):.1f}% reduction chosen by the "
        f"caller. Any agency (or a compromised sub-agent) can therefore set its own fare, and the "
        f"supplier is invoiced at the reduced value. {next((r.detail for r in broken), '')}"
    )
    remediation = (
        "Never trust monetary fields from the client. Re-price server-side from the fare/quote id, "
        "compare against the original quote, and reject any reduction beyond an authorised "
        "reissue/refund policy. Make `amount` read-only in the request schema (mass-assignment guard) "
        "and assert `final >= quoted` in the write path."
    )

    return make_finding(
        factory=ctx.factory,
        title=f"Fare tampering — booking {bid} rebooked at {ledger.final:.2f} against a {ledger.quoted:.2f} quote",
        vuln_class="fare_tampering",
        method="POST",
        endpoint=ctx.paths.rebook,
        capsule=cap,
        severity=severity,
        owner=ctx.owner,
        owasp="API6:2023 Unrestricted Access to Sensitive Business Flows",
        cwe="CWE-472 External Control of Assumed-Immutable Web Parameter",
        impact=impact,
        remediation=remediation,
        extracted={
            "booking_id": bid,
            "ledger": ledger.to_dict(),
            "violated_invariants": [r.to_dict() for r in broken],
            "delta": round(ledger.quoted - ledger.final, 2),
        },
        retest={"mode": "re-execute", "test_id": "logic_fare_tampering", "role": ctx.role},
        notes=ctx.notes,
    )
