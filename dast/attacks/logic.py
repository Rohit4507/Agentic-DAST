"""Business-logic attacks, verified by ledger invariants.

Each attack drives a real flow on a **synthetic booking created for the purpose**, then
reads the ledger back and checks invariants. The invariant check is the verifier, so a
finding here is arithmetic, not opinion — which is exactly why logic bugs are the place
to beat conventional scanners on precision as well as depth.

Write operations are gated (:mod:`dast.gate`); reads are not.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..errors import ApprovalDenied, ScopeViolation, TransportError, STOPPING
from ..gate import ApprovalGate
from ..http import Client, Response
from ..fields import first
from ..model import classify_data
from ..profile import FlowProfile, FlowPathsView, IdentifierSpec, LedgerSpec, TargetProfile
from ..report.severity import from_finding_kind
from ..verify.engine import Capsule, excerpt
from ..verify.invariants import Ledger, violations
from ..verify.ledger_source import LedgerSource, build_ledger_source
from .common import FindingFactory, make_finding


@dataclass
class LogicContext:
    """Everything a logic test needs, with the target's vocabulary injected.

    ``flow`` is the profile's step map (paths *and* request bodies), ``ledger`` is
    whichever adapter the profile selected, and ``ids`` says where identity/boundary
    live in a body.  Nothing here is mock-shaped any more.
    """

    client: Client
    gate: ApprovalGate
    factory: FindingFactory
    role: str
    owner: str = "unassigned"
    flow: FlowProfile = field(default_factory=lambda: TargetProfile.mock_defaults().flows)
    ledger: LedgerSource | None = None
    ids: IdentifierSpec = field(default_factory=IdentifierSpec)
    notes: list[str] = field(default_factory=list)

    @property
    def paths(self) -> FlowPathsView:
        """Path view, so report copy can name the target's real endpoints."""
        return self.flow.view()

    @property
    def ledger_source(self) -> LedgerSource:
        if self.ledger is None:
            self.ledger = build_ledger_source(LedgerSpec(adapter="http", endpoint=self.flow.path("ledger")), self.client)
        return self.ledger


# --------------------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------------------


def _call(ctx: LogicContext, method: str, path: str, *, body: Any = None, note: str = "") -> Response:
    return ctx.client.request(
        method, path, role=ctx.role, json=body, component="logic", note=note
    )


def _step(ctx: LogicContext, name: str, *, note: str = "", **values: Any) -> Response:
    """Call a profile step: the body comes from the template, not from literals here.

    A missing step is not an exception -- the planner should not have scheduled the
    test -- but if it did, the note makes the reason visible instead of blaming the
    target for a 404.
    """
    spec = ctx.flow.get(name)
    if spec is None:
        raise ScopeViolation(
            "no-step",
            detail=f"profile has no {name!r} step; cannot run this flow",
        )
    return _call(ctx, spec.method, spec.url(**values), body=spec.payload(**values), note=note or name)


def _ledger(ctx: LogicContext, booking_id: str) -> Ledger | None:
    source = ctx.ledger_source
    payload = source.read(booking_id, role=ctx.role)
    if payload is None:
        ctx.notes.append(source.last_error or f"ledger unreadable for {booking_id}; finding voided")
        return None
    try:
        return Ledger.from_api(payload)
    except (TypeError, ValueError) as exc:
        ctx.notes.append(f"ledger payload for {booking_id} could not be interpreted: {exc}")
        return None


def _ledger_evidence(ctx: LogicContext, booking_id: str) -> Response:
    """The capsule step for the ledger read.

    For an HTTP ledger this is the real response the adapter just consumed.  For a
    fixture it is the canonical payload the operator exported, clearly labelled as
    such -- evidence a human can check, not a synthesised "200 OK".
    """
    source = ctx.ledger_source
    raw = getattr(source, "last_response", None)
    if isinstance(raw, Response):
        return raw
    payload = source.read(booking_id, role=ctx.role)
    body = json.dumps(payload or {}, indent=2).encode("utf-8")
    return Response(
        method="GET",
        url=f"ledger:{source.describe()}",
        status=200 if payload is not None else 0,
        headers={"Content-Type": "application/json", "X-Evidence": "operator-export"},
        body=body,
        elapsed_ms=0.0,
    )


def _open_booking(ctx: LogicContext, *, amount: float, pax: int = 1) -> tuple[str, Response] | None:
    try:
        resp = _step(ctx, "hold", note="synthetic-booking", pax=pax, amount=amount)
    except STOPPING:
        raise
    except ScopeViolation as exc:
        ctx.notes.append(f"cannot create a synthetic booking: {exc}")
        return None
    except TransportError as exc:
        ctx.notes.append(f"could not create a synthetic booking: {exc}")
        return None
    if resp.status >= 400:
        ctx.notes.append(f"hold returned {resp.status}")
        return None
    try:
        body = resp.json()
    except ValueError:
        ctx.notes.append("hold response was not JSON")
        return None
    if not isinstance(body, dict):
        ctx.notes.append("hold response was not a JSON object")
        return None
    id_from = ctx.flow.get("hold").id_from if ctx.flow.get("hold") else ""
    candidates = [id_from] if id_from else []
    candidates.extend(ctx.ids.identity_paths())
    ident = first(body, candidates)
    if ident is None:
        ctx.notes.append(
            f"hold response had none of {candidates}; set flows.hold.id_from in the profile"
        )
        return None
    return str(ident), resp


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
        pay = _step(ctx, "pay", note="pay", id=bid, amount=amount)
        cancel = _step(ctx, "cancel", note="cancel", id=bid)
        first = _step(ctx, "refund", note="refund-1", id=bid, amount=amount)
        second = _step(ctx, "refund", note="refund-2", id=bid, amount=amount)
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
    cap.add("ledger", _ledger_evidence(ctx, bid), role=ctx.role)

    severity = from_finding_kind("double_refund", money=True, write=True)
    first_line, _ = excerpt(second, max_lines=2)
    impact = (
        f"`POST {ctx.paths.refund}` accepts a second refund for a {ctx.ids.object_noun} that is already refunded. "
        f"On {ctx.ids.object_noun} {bid} ({ledger.summary_line()}), the ledger shows "
        f"{ledger.successful_refunds} successful refunds totalling {ledger.refunded:.2f} against "
        f"{ledger.paid:.2f} paid. Each replay of the same request moves money again: "
        f"{next((r.detail for r in broken), '')}. "
        f"Nothing in the request changes between calls, so this is replayable at will."
    )
    remediation = (
        "Make refund issuance idempotent and state-guarded in one transaction: lock the record, "
        "reject when `refunds.any(status == 'settled')`, and require a client-supplied idempotency key. "
        "Enforce the ledger invariant `Σrefunds ≤ Σpayments` in the database as a constraint so a "
        "future handler cannot regress it. Last response: " + first_line.replace("\n", " ")[:200]
    )

    finding = make_finding(
        factory=ctx.factory,
        title=f"Double refund — {ctx.ids.object_noun} {bid} was refunded twice",
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
        confirm = _step(ctx, "confirm", note="confirm-without-payment", id=bid)
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
    cap.add("ledger", _ledger_evidence(ctx, bid), role=ctx.role)

    severity = from_finding_kind("skipped_payment", money=True, write=True)
    impact = (
        f"`POST {ctx.paths.confirm}` moves a {ctx.ids.object_noun} to CONFIRMED with no payment recorded. "
        f"{ctx.ids.object_noun.capitalize()} {bid}: status={ledger.status}, paid={ledger.paid:.2f}, quoted={ledger.quoted:.2f}. "
        f"The state machine permits the transition HELD -> CONFIRMED, skipping PAY, so a caller that "
        f"never calls `{ctx.paths.pay}` still gets a confirmed, ticketed {ctx.ids.object_noun} — an unpaid "
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
        title=f"Skipped payment — {ctx.ids.object_noun} {bid} confirmed with {ledger.paid:.2f} paid",
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
        rebook = _step(ctx, "rebook", note="fare-tamper", id=bid, quoted=quoted, tampered=tampered)
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
    cap.add("ledger", _ledger_evidence(ctx, bid), role=ctx.role)

    severity = from_finding_kind("fare_tampering", money=True, write=True)
    impact = (
        f"`POST {ctx.paths.rebook}` writes the client-supplied `amount` straight into the {ctx.ids.object_noun}'s "
        f"final amount. {ctx.ids.object_noun.capitalize()} {bid} was quoted {ledger.quoted:.2f} and rebooked at "
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
        title=(
            f"Fare tampering — {ctx.ids.object_noun} {bid} rebooked at "
            f"{ledger.final:.2f} against a {ledger.quoted:.2f} quote"
        ),
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
