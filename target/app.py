"""A deliberately vulnerable B2B travel API, for local use only.

    python -m target.app --port 8080

⚠️  THIS IS INSECURE BY DESIGN. It exists so the DAST harness has a target with known,
    planted bugs that can be verified end-to-end without touching anyone's systems.
    It binds to localhost and refuses to start with ``--host 0.0.0.0`` unless
    ``ALLOW_UNSAFE_BIND=1`` is set. Never deploy it anywhere.

Planted issues (mapped to the hackathon's vulnerability classes):

    BOLA              GET  /api/booking/{id}                  no ownership check
    Zombie API        GET  /api/v1/booking/{id}                old version, no auth
    Zombie API        GET  /api/old/agency/{id}/summary        retired route, no auth
    Zombie API        GET  /api/test/debug                     debug route left in prod
    Shadow API        GET  /api/internal/agency/{id}/export     in use, undocumented
    Business logic    POST /api/refund                         double refund allowed
    Business logic    POST /api/confirm                        payment step skippable
    Business logic    POST /api/rebook                         client-supplied fare honoured

Correctly implemented on purpose (so "no false positive" is provable):
    GET  /api/bookings          filtered to the caller's agency, 401 without a token
    GET  /api/ledger/{id}       ownership enforced
    GET  /api/booking/{id}      unknown id -> 404 (the negative control)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

# --------------------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------------------

TOKENS = {
    "tok-agency-a": "AGENCY-A",
    "tok-agency-b": "AGENCY-B",
}

AGENCY_NAMES = {"AGENCY-A": "Agency Alpha Travel", "AGENCY-B": "Agency Beta Voyages"}


def _ts(days_ago: float = 0.0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")


@dataclass
class Booking:
    id: str
    agency_id: str
    status: str = "HELD"
    quoted_amount: float = 0.0
    final_amount: float = 0.0
    pax_count: int = 1
    created_at: str = field(default_factory=_ts)
    payments: list[dict[str, Any]] = field(default_factory=list)
    refunds: list[dict[str, Any]] = field(default_factory=list)
    traveller: dict[str, str] = field(default_factory=dict)

    @property
    def paid(self) -> float:
        return round(sum(p["amount"] for p in self.payments), 2)

    def to_dict(self, *, full: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "bookingId": self.id,
            "agencyId": self.agency_id,
            "status": self.status,
            "quotedAmount": round(self.quoted_amount, 2),
            "finalAmount": round(self.final_amount, 2),
            "paxCount": self.pax_count,
            "createdAt": self.created_at,
        }
        if full:
            d["traveller"] = dict(self.traveller)
        return d


class Store:
    def __init__(self) -> None:
        self.bookings: dict[str, Booking] = {}
        self.lock = threading.RLock()
        self.request_count = 0
        self.seed()

    def seed(self) -> None:
        with self.lock:
            self.bookings.clear()
            self._add(
                Booking(
                    id="8842",
                    agency_id="AGENCY-A",
                    status="CONFIRMED",
                    quoted_amount=48500.0,
                    final_amount=48500.0,
                    pax_count=2,
                    traveller={
                        "name": "SYNTHETIC Traveller A1",
                        "passport": "P<SYNTHA1<<0001",
                        "email": "a1@example.test",
                        "phone": "+91-00000-00001",
                    },
                ),
                paid=48500.0,
            )
            self._add(
                Booking(
                    id="8843",
                    agency_id="AGENCY-A",
                    status="PAID",
                    quoted_amount=12250.0,
                    final_amount=12250.0,
                    pax_count=1,
                    traveller={
                        "name": "SYNTHETIC Traveller A2",
                        "passport": "P<SYNTHA2<<0002",
                        "email": "a2@example.test",
                        "phone": "+91-00000-00002",
                    },
                ),
                paid=12250.0,
            )
            self._add(
                Booking(
                    id="9101",
                    agency_id="AGENCY-B",
                    status="CONFIRMED",
                    quoted_amount=31000.0,
                    final_amount=31000.0,
                    pax_count=3,
                    traveller={
                        "name": "SYNTHETIC Traveller B1",
                        "passport": "P<SYNTHB1<<0003",
                        "email": "b1@example.test",
                        "phone": "+91-00000-00003",
                    },
                ),
                paid=31000.0,
            )

    def _add(self, b: Booking, *, paid: float = 0.0) -> Booking:
        if paid:
            b.payments.append({"amount": paid, "ts": _ts(2.0), "kind": "initial"})
        b.final_amount = b.final_amount or b.quoted_amount
        self.bookings[b.id] = b
        return b

    def get(self, booking_id: str) -> Booking | None:
        with self.lock:
            return self.bookings.get(str(booking_id))

    def list_for(self, agency_id: str) -> list[Booking]:
        with self.lock:
            return [b for b in self.bookings.values() if b.agency_id == agency_id]

    def create(self, agency_id: str, pax: int, amount: float, traveller: dict[str, str] | None = None) -> Booking:
        with self.lock:
            bid = str(8000 + len(self.bookings) + int(uuid.uuid4().int % 900))
            while bid in self.bookings:
                bid = str(int(bid) + 1)
            b = Booking(
                id=bid,
                agency_id=agency_id,
                quoted_amount=float(amount),
                final_amount=float(amount),
                pax_count=int(pax),
                traveller=traveller
                or {
                    "name": "SYNTHETIC Test Pax",
                    "passport": "P<SYNTHT<<0000",
                    "email": "pax@example.test",
                    "phone": "+91-00000-00000",
                },
            )
            self.bookings[bid] = b
            return b


# --------------------------------------------------------------------------------------
# routing
# --------------------------------------------------------------------------------------

Route = tuple[str, re.Pattern[str], Callable[["Api", re.Match[str], dict, dict], tuple[int, Any]]]
ROUTES: list[Route] = []


def route(method: str, pattern: str):
    def deco(fn):
        ROUTES.append((method, re.compile(f"^{pattern}$"), fn))
        return fn

    return deco


def _pii_ok(body: dict) -> dict:
    return body


class Api:
    """Handlers. Each returns (status, payload)."""

    def __init__(self, store: Store) -> None:
        self.store = store

    # -- helpers -------------------------------------------------------------------

    @staticmethod
    def agency_of(headers: dict[str, str]) -> str | None:
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return None
        return TOKENS.get(auth.split(None, 1)[1].strip())

    # -- public --------------------------------------------------------------------

    @route("GET", "/healthz")
    def healthz(self, m, body, h):
        return 200, {"status": "ok", "service": "mock-travel-api"}

    @route("GET", "/api/bookings")
    def list_bookings(self, m, body, h):
        agency = self.agency_of(h)
        if not agency:
            return 401, {"error": "authentication required"}
        rows = [b.to_dict(full=False) for b in self.store.list_for(agency)]
        return 200, {"agencyId": agency, "count": len(rows), "bookings": rows}

    @route("GET", r"/api/booking/(?P<bid>[A-Za-z0-9_-]{1,32})")
    def get_booking(self, m, body, h):
        """⚠️ BOLA: authenticates, but never checks that the caller owns the booking."""
        if not self.agency_of(h):
            return 401, {"error": "authentication required"}
        b = self.store.get(m.group("bid"))
        if b is None:
            return 404, {"error": "booking not found", "bookingId": m.group("bid")}
        return 200, b.to_dict()

    @route("GET", r"/api/ledger/(?P<bid>[A-Za-z0-9_-]{1,32})")
    def ledger(self, m, body, h):
        agency = self.agency_of(h)
        if not agency:
            return 401, {"error": "authentication required"}
        b = self.store.get(m.group("bid"))
        if b is None:
            return 404, {"error": "booking not found"}
        if b.agency_id != agency:  # correctly enforced: no detection here
            return 403, {"error": "forbidden"}
        return 200, {
            "bookingId": b.id,
            "payments": list(b.payments),
            "refunds": list(b.refunds),
            "status": b.status,
            "quotedAmount": round(b.quoted_amount, 2),
            "finalAmount": round(b.final_amount, 2),
        }

    # -- booking flow --------------------------------------------------------------

    @route("POST", "/api/hold")
    def hold(self, m, body, h):
        agency = self.agency_of(h)
        if not agency:
            return 401, {"error": "authentication required"}
        try:
            amount = float(body.get("amount", 0))
            pax = int(body.get("pax", 1))
        except (TypeError, ValueError):
            return 400, {"error": "amount and pax must be numeric"}
        b = self.store.create(agency, pax, amount, body.get("traveller"))
        return 201, b.to_dict()

    @route("POST", "/api/pay")
    def pay(self, m, body, h):
        agency = self.agency_of(h)
        if not agency:
            return 401, {"error": "authentication required"}
        b = self.store.get(str(body.get("booking", "")))
        if not b:
            return 404, {"error": "booking not found"}
        try:
            amount = float(body.get("amount", b.final_amount))
        except (TypeError, ValueError):
            return 400, {"error": "amount must be numeric"}
        with self.store.lock:
            b.payments.append({"amount": amount, "ts": _ts(0), "kind": "payment"})
            b.status = "PAID"
        return 200, {"bookingId": b.id, "paid": b.paid, "status": b.status}

    @route("POST", "/api/confirm")
    def confirm(self, m, body, h):
        """⚠️ Business logic: reaches CONFIRMED with zero payment."""
        agency = self.agency_of(h)
        if not agency:
            return 401, {"error": "authentication required"}
        b = self.store.get(str(body.get("booking", "")))
        if not b:
            return 404, {"error": "booking not found"}
        with self.store.lock:
            b.status = "CONFIRMED"
        return 200, {"bookingId": b.id, "status": b.status, "paid": b.paid}

    @route("POST", "/api/cancel")
    def cancel(self, m, body, h):
        agency = self.agency_of(h)
        if not agency:
            return 401, {"error": "authentication required"}
        b = self.store.get(str(body.get("booking", "")))
        if not b:
            return 404, {"error": "booking not found"}
        with self.store.lock:
            b.status = "CANCELLED"
        return 200, {"bookingId": b.id, "status": b.status}

    @route("POST", "/api/refund")
    def refund(self, m, body, h):
        """⚠️ Business logic: no single-refund guard, no refund <= paid check."""
        agency = self.agency_of(h)
        if not agency:
            return 401, {"error": "authentication required"}
        b = self.store.get(str(body.get("booking", "")))
        if not b:
            return 404, {"error": "booking not found"}
        try:
            amount = float(body.get("amount", b.paid or b.final_amount))
        except (TypeError, ValueError):
            return 400, {"error": "amount must be numeric"}
        with self.store.lock:
            b.refunds.append({"amount": amount, "status": "ok", "ts": _ts(0)})
            b.status = "REFUNDED"
        return 200, {"bookingId": b.id, "refunded": amount, "refundCount": len(b.refunds)}

    @route("POST", "/api/refund/bulk")
    def refund_bulk(self, m, body, h):
        """Destructive by design and explicitly deny-listed in scope.json."""
        return 202, {"status": "queued", "count": len(body.get("bookings", []))}

    @route("POST", "/api/rebook")
    def rebook(self, m, body, h):
        """⚠️ Business logic: a client-supplied amount overrides the server-side fare."""
        agency = self.agency_of(h)
        if not agency:
            return 401, {"error": "authentication required"}
        b = self.store.get(str(body.get("booking", "")))
        if not b:
            return 404, {"error": "booking not found"}
        try:
            amount = float(body.get("amount", b.final_amount))
        except (TypeError, ValueError):
            return 400, {"error": "amount must be numeric"}
        with self.store.lock:
            b.final_amount = amount
            b.status = "REBOOKED"
        return 200, {"bookingId": b.id, "finalAmount": b.final_amount, "quotedAmount": b.quoted_amount}

    # -- legacy / internal (zombie + shadow) ---------------------------------------

    @route("GET", r"/api/v1/booking/(?P<bid>[A-Za-z0-9_-]{1,32})")
    def v1_booking(self, m, body, h):
        """⚠️ Zombie + unauthenticated data exposure: the v1 contract never had auth."""
        b = self.store.get(m.group("bid"))
        if b is None:
            return 404, {"error": "not found"}
        payload = b.to_dict()
        payload["apiVersion"] = "v1"
        return 200, payload

    @route("GET", r"/api/old/agency/(?P<aid>[A-Za-z0-9_-]{1,32})/summary")
    def old_agency_summary(self, m, body, h):
        """⚠️ Zombie: retired route, still answering, no auth.

        Unknown agencies 404, so a negative control on this route is meaningful.
        """
        rows = self.store.list_for(m.group("aid"))
        if not rows:
            return 404, {"error": "unknown agency", "agencyId": m.group("aid")}
        return 200, {
            "agencyId": m.group("aid"),
            "agencyName": AGENCY_NAMES.get(m.group("aid"), "unknown"),
            "bookingCount": len(rows),
            "totalValue": round(sum(x.final_amount for x in rows), 2),
        }

    @route("GET", "/api/test/debug")
    def debug(self, m, body, h):
        """⚠️ Zombie: debug route left in production."""
        return 200, {
            "env": "staging",
            "python": sys.version.split()[0],
            "bookingsInMemory": len(self.store.bookings),
            "featureFlags": {"new_fare_engine": True, "legacy_auth": True},
        }

    @route("GET", r"/api/internal/agency/(?P<aid>[A-Za-z0-9_-]{1,32})/export")
    def internal_export(self, m, body, h):
        """⚠️ Shadow + unauthenticated: used by an internal tool, documented nowhere."""
        rows = self.store.list_for(m.group("aid"))
        return 200, {
            "agencyId": m.group("aid"),
            "exportedAt": _ts(0),
            "bookings": [b.to_dict() for b in rows],
        }

    @route("GET", "/api/admin/users")
    def admin_users(self, m, body, h):
        return 200, {"users": [{"role": "admin", "agency": "*"}], "warning": "should be unreachable"}


# --------------------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "MockTravelAPI/0.1"
    protocol_version = "HTTP/1.1"
    api: Api = None  # set by make_server
    verbose: bool = False

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        from urllib.parse import urlsplit

        path = urlsplit(self.path).path or "/"
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        headers = {k.lower(): v for k, v in self.headers.items()}
        self.api.store.request_count += 1

        for m_method, pattern, fn in ROUTES:
            if m_method != method:
                continue
            match = pattern.match(path)
            if match:
                try:
                    status, payload = fn(self.api, match, body, headers)
                except Exception as exc:  # noqa: BLE001
                    status, payload = 500, {"error": f"handler error: {exc}"}
                if self.verbose:
                    print(f"  [{status}] {method:6s} {path}", file=sys.stderr)
                self._send(status, payload)
                return
        if self.verbose:
            print(f"  [404] {method:6s} {path}", file=sys.stderr)
        self._send(404, {"error": "no route", "path": path})

    def _send(self, status: int, payload: Any) -> None:
        blob = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("X-Environment", "staging")
        self.end_headers()
        self.wfile.write(blob)

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
        if self.verbose:
            super().log_message(fmt, *args)


def make_server(port: int = 0, host: str = "127.0.0.1", verbose: bool = False) -> ThreadingHTTPServer:
    store = Store()
    Handler.api = Api(store)
    Handler.verbose = verbose
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Deliberately vulnerable mock travel API (local only)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("MOCK_PORT", "8080")))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--verbose", action="store_true", help="log every request to stderr")
    args = ap.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1") and os.environ.get("ALLOW_UNSAFE_BIND") != "1":
        print(
            "refusing to bind a deliberately vulnerable app to a non-loopback address.\n"
            "Set ALLOW_UNSAFE_BIND=1 only if you understand the risk.",
            file=sys.stderr,
        )
        return 2

    server = make_server(args.port, args.host, args.verbose)
    port = server.server_address[1]
    print(f"mock-travel-api listening on http://{args.host}:{port}")
    print(f"tokens: {', '.join(TOKENS)}")
    print("⚠️  deliberately vulnerable — local use only")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
