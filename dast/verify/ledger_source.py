"""Where the money proof comes from.

The invariant tests in :mod:`dast.verify.invariants` are arithmetic: they need a
booking's payments and refunds, not an opinion.  Version 1 read that from
``GET /api/ledger/{id}`` -- a convenience endpoint the bundled mock happens to expose
and a real travel platform almost never does.

So the *source* is now an adapter behind :class:`LedgerSource`:

* :class:`HttpLedgerSource` -- the target does expose a ledger/statement route.  Field
  names are mapped from the profile, so ``data.reversals[].value`` and
  ``refunds[].amount`` feed the same invariant.
* :class:`FixtureLedgerSource` -- the target does not, and the operator exports a
  JSON/CSV statement after the run (from the sandbox database or the finance system).
* :class:`NullLedgerSource` -- nothing configured.  Every logic test then declines to
  run with a reason, instead of inventing a proof.

The rule that keeps this honest: **an unreadable ledger voids the finding.**  Adapter
failure is never "assume the invariant held" and never "assume it broke".
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import STOPPING, ScopeViolation, TransportError
from ..fields import as_float, as_int, dig, first, rows
from ..http import Client, Response
from ..profile import LedgerSpec

#: Canonical name -> the keys we will try in the target's payload, in order.
_CANONICAL: dict[str, tuple[str, ...]] = {
    "status": ("status", "state", "bookingStatus", "booking_status"),
    "quotedAmount": ("quotedAmount", "quoted_amount", "quoted", "quoteTotal", "quote_total"),
    "finalAmount": ("finalAmount", "final_amount", "final", "total", "grandTotal", "final_total"),
    "paxCount": ("paxCount", "pax_count", "pax", "passengers", "paxTotal"),
    "payments": ("payments", "settlements", "charges", "receipts"),
    "refunds": ("refunds", "reversals", "reimbursements", "creditNotes", "credit_notes"),
}

#: Canonical field inside one row of ``payments``/``refunds``.
_ROW_KEYS: dict[str, tuple[str, ...]] = {
    "amount": ("amount", "value", "amt", "total", "refundedAmount", "settledAmount"),
    "status": ("status", "state", "result", "settlementStatus"),
}


@dataclass
class LedgerRead:
    """One attempt to read a ledger.  ``payload`` is canonical or ``None``."""

    payload: dict[str, Any] | None = None
    status: int = 0
    error: str = ""
    source: str = ""

    @property
    def ok(self) -> bool:
        return self.payload is not None


class LedgerSource:
    """Base class.  Subclasses return a *canonical* payload or ``None``."""

    name = "none"
    last_error = ""

    def read(self, booking_id: str, *, role: str | None = None) -> dict[str, Any] | None:
        raise NotImplementedError

    def describe(self) -> str:
        return self.name


def canonicalise(payload: Mapping[str, Any], spec: LedgerSpec) -> dict[str, Any]:
    """Normalise whatever the target returns into the shape the invariants read."""
    out: dict[str, Any] = {}
    for canon, defaults in _CANONICAL.items():
        paths = [spec.map[canon]] if canon in spec.map else []
        paths.extend(defaults)
        value = first(payload, paths)
        if value is None:
            continue
        if canon in ("payments", "refunds"):
            out[canon] = [_canonical_row(row, spec) for row in rows(value)]
        elif canon in ("quotedAmount", "finalAmount"):
            out[canon] = as_float(value)
        elif canon == "paxCount":
            out[canon] = as_int(value, 1)
        else:
            out[canon] = value if isinstance(value, str) else str(value)
    if spec.id_field and spec.id_field not in out:
        value = first(payload, (spec.id_field, "id", "bookingId"))
        if value is not None:
            out[spec.id_field] = str(value)
    return out


def _canonical_row(row: Mapping[str, Any], spec: LedgerSpec) -> dict[str, Any]:
    out: dict[str, Any] = {}
    amount_path = spec.item_map.get("amount")
    status_path = spec.item_map.get("status")
    amount = dig(row, amount_path) if amount_path else first(row, _ROW_KEYS["amount"])
    status = dig(row, status_path) if status_path else first(row, _ROW_KEYS["status"])
    out["amount"] = as_float(amount)
    if status is not None:
        out["status"] = status if isinstance(status, str) else str(status)
    return out


# --------------------------------------------------------------------------------------
# adapters
# --------------------------------------------------------------------------------------


class HttpLedgerSource(LedgerSource):
    """The target exposes a statement route; the profile maps its field names."""

    name = "http"

    def __init__(self, client: Client, spec: LedgerSpec) -> None:
        self.client = client
        self.spec = spec
        self.last_error = ""

    def read(self, booking_id: str, *, role: str | None = None) -> dict[str, Any] | None:
        self.last_error = ""
        endpoint = self.spec.endpoint.replace("{id}", booking_id)
        if "{" in endpoint:  # a placeholder we do not know how to fill
            self.last_error = f"ledger endpoint {self.spec.endpoint!r} still has a placeholder"
            return None
        try:
            resp: Response = self.client.request(
                "GET",
                endpoint,
                role=role,
                component="logic",
                note=f"ledger:{booking_id}",
            )
        except STOPPING:
            raise
        except (ScopeViolation, TransportError) as exc:
            self.last_error = f"ledger read failed for {booking_id}: {exc}"
            return None
        if resp.status != 200:
            self.last_error = f"ledger read for {booking_id} returned {resp.status}"
            return None
        try:
            payload = resp.json()
        except ValueError:
            self.last_error = f"ledger for {booking_id} was not JSON"
            return None
        if not isinstance(payload, Mapping):
            self.last_error = f"ledger for {booking_id} was not a JSON object"
            return None
        return canonicalise(payload, self.spec)

    def describe(self) -> str:
        return f"http {self.spec.endpoint}"


class FixtureLedgerSource(LedgerSource):
    """No statement route: read an export the operator produced after the run.

    Accepted shapes, because this is what actually gets exported:

    * JSON object keyed by booking id
    * JSON array of booking objects (any of ``bookingId``/``id``/``booking_id``)
    * CSV with ``booking_id,kind,amount,status`` where ``kind`` is payment|refund
    """

    name = "fixture"

    def __init__(self, path: str | Path, spec: LedgerSpec | None = None) -> None:
        self.path = Path(path)
        self.spec = spec or LedgerSpec()
        self.last_error = ""

    def read(self, booking_id: str, *, role: str | None = None) -> dict[str, Any] | None:
        self.last_error = ""
        if not self.path.exists():
            self.last_error = f"ledger fixture missing: {self.path}"
            return None
        try:
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.last_error = f"ledger fixture unreadable: {exc}"
            return None
        if not text.strip():
            self.last_error = f"ledger fixture empty: {self.path}"
            return None
        payload = self._from_text(text, booking_id)
        if payload is None:
            self.last_error = f"no ledger row for {booking_id} in {self.path}"
            return None
        return canonicalise(payload, self.spec)

    def _from_text(self, text: str, booking_id: str) -> Mapping[str, Any] | None:
        stripped = text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                raw = json.loads(text)
            except json.JSONDecodeError as exc:
                self.last_error = f"ledger fixture is not valid JSON: {exc}"
                return None
            if isinstance(raw, dict):
                entry = raw.get(booking_id)
                if isinstance(entry, Mapping):
                    return entry
                # maybe a single booking object, or keyed by an int
                for key, value in raw.items():
                    if str(key) == str(booking_id) and isinstance(value, Mapping):
                        return value
            if isinstance(raw, list):
                for item in raw:
                    if not isinstance(item, Mapping):
                        continue
                    ident = first(item, ("bookingId", "id", "booking_id", "orderId", "order_id"))
                    if ident is not None and str(ident) == str(booking_id):
                        return item
            return None
        return self._from_csv(text, booking_id)

    def _from_csv(self, text: str, booking_id: str) -> Mapping[str, Any] | None:
        reader = csv.DictReader(text.splitlines())
        if not reader.fieldnames:
            return None
        matching = [row for row in reader if str(row.get("booking_id") or row.get("bookingId") or "") == str(booking_id)]
        if not matching:
            return None
        payments: list[dict[str, Any]] = []
        refunds: list[dict[str, Any]] = []
        out: dict[str, Any] = {"bookingId": booking_id}
        for row in matching:
            kind = str(row.get("kind") or row.get("type") or "").lower()
            item = {"amount": row.get("amount"), "status": row.get("status") or "ok"}
            if "refund" in kind or "reversal" in kind:
                refunds.append(item)
            elif "pay" in kind or "settle" in kind or "charge" in kind:
                payments.append(item)
            if row.get("status") and kind in ("booking", "order", ""):
                out["status"] = row["status"]
            if row.get("quoted_amount"):
                out["quotedAmount"] = row["quoted_amount"]
            if row.get("final_amount"):
                out["finalAmount"] = row["final_amount"]
        out["payments"] = payments
        out["refunds"] = refunds
        return out

    def describe(self) -> str:
        return f"fixture {self.path}"


class NullLedgerSource(LedgerSource):
    """Nothing configured.  Every logic test declines, with the reason recorded."""

    name = "none"

    def __init__(self, reason: str = "no ledger adapter configured in the profile") -> None:
        self.reason = reason
        self.last_error = reason

    def read(self, booking_id: str, *, role: str | None = None) -> dict[str, Any] | None:
        self.last_error = self.reason
        return None

    def describe(self) -> str:
        return f"none ({self.reason})"


def build_ledger_source(spec: LedgerSpec, client: Client) -> LedgerSource:
    """Pick the adapter from the profile.  Never falls back to a guess."""
    if spec.adapter == "http" and spec.endpoint:
        return HttpLedgerSource(client, spec)
    if spec.adapter == "fixture" and spec.path:
        return FixtureLedgerSource(spec.path, spec)
    return NullLedgerSource(
        "profile has no usable ledger adapter "
        f"(adapter={spec.adapter!r}, endpoint={spec.endpoint!r}, path={spec.path!r})"
    )
