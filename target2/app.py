"""A second deliberately-vulnerable target, built to disprove the mock's vocabulary.

The bundled ``target/`` app speaks ``/api/...`` with ``bookingId``/``agencyId`` at the
top level of the body.  This one speaks ``/v2/...``, nests everything under ``data``,
uses ``tenant`` instead of ``agencyId``, calls money ``value`` and statuses
``state``, and exposes its ledger as ``settlements``/``reversals`` rather than
``payments``/``refunds``.

It has the *same classes* of bug -- broken object-level authorization, an
unauthenticated legacy route, an undocumented internal route, a double refund, a
skipped payment step, and a client-controlled reprice -- so a scanner that is really
target-independent finds them all through a different profile, with no code change.

Nothing here is meant to be deployed.  It binds loopback only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

TENANT_A = "TN-A"
TENANT_B = "TN-B"

TOKENS = {
    "tok-tenant-a": TENANT_A,
    "tok-tenant-b": TENANT_B,
}

#: Stable ids, so a capture file stays meaningful across restarts.
SEED = {
    "8f14e45f-ceea-467f-a1b2-1c9e2d3f4a01": {
        "tenant": TENANT_A,
        "status": "HELD",
        "quote_total": 4800.0,
        "final_total": 4800.0,
        "pax": 2,
        "customer": {
            "name": "A. Sharma",
            "email": "a.sharma@example-agency.test",
            "phone": "+91-90000-00001",
            "passport": "P1234567",
        },
        "settlements": [],
        "reversals": [],
    },
    "8f14e45f-ceea-467f-a1b2-1c9e2d3f4a02": {
        "tenant": TENANT_B,
        "status": "HELD",
        "quote_total": 6100.0,
        "final_total": 6100.0,
        "pax": 1,
        "customer": {
            "name": "B. Das",
            "email": "b.das@example-agency.test",
            "phone": "+91-90000-00002",
            "passport": "P7654321",
        },
        "settlements": [],
        "reversals": [],
    },
}


class Store:
    """In-memory orders.  Deliberately naive: that is the point of the app."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.orders: dict[str, dict[str, Any]] = json.loads(json.dumps(SEED))

    def get(self, order_id: str) -> dict[str, Any] | None:
        with self.lock:
            order = self.orders.get(order_id)
            return json.loads(json.dumps(order)) if order else None

    def create(self, tenant: str, pax: int, amount: float) -> str:
        order_id = str(uuid.uuid4())
        with self.lock:
            self.orders[order_id] = {
                "tenant": tenant,
                "status": "HELD",
                "quote_total": float(amount),
                "final_total": float(amount),
                "pax": int(pax),
                "customer": {
                    "name": "Synthetic Pax",
                    "email": "synthetic@example.test",
                    "phone": "+91-90000-00000",
                    "passport": "P0000000",
                },
                "settlements": [],
                "reversals": [],
            }
        return order_id

    def mutate(self, order_id: str, fn) -> dict[str, Any] | None:  # noqa: ANN001
        with self.lock:
            order = self.orders.get(order_id)
            if order is None:
                return None
            fn(order)
            return json.loads(json.dumps(order))

    def list_for(self, tenant: str) -> list[str]:
        with self.lock:
            return [oid for oid, o in self.orders.items() if o["tenant"] == tenant]


def _money(body: dict[str, Any], *names: str, default: float = 0.0) -> float:
    for name in names:
        if name in body:
            try:
                return float(body[name])
            except (TypeError, ValueError):
                return default
    return default


class Api:
    def __init__(self, store: Store) -> None:
        self.store = store

    # -- routing --------------------------------------------------------------------
    def handle(self, method: str, path: str, body: dict[str, Any], tenant: str | None) -> tuple[int, dict[str, Any]]:
        parts = [p for p in path.strip("/").split("/") if p]

        if method == "GET" and parts == ["v2", "health"]:
            return 200, {"ok": True}

        # --- legacy route: no authentication at all (zombie) ----------------------
        if method == "GET" and len(parts) == 4 and parts[:2] == ["v2", "legacy"] and parts[2] == "orders":
            order = self.store.get(parts[3])
            if order is None:
                return 404, {"error": "not found"}
            return 200, {"order": order}  # no tenant, no token, full PII

        # --- internal reporting: undocumented in every bundle (shadow) ------------
        if method == "GET" and parts == ["v2", "internal", "reports"]:
            return 200, {
                "reports": [
                    {"report": "settlement_summary", "gross": 41250.0, "tenant": TENANT_A},
                    {"report": "refund_exceptions", "count": 3, "tenant": TENANT_B},
                ],
                "generated_by": "reports-service",
            }

        # everything below needs a bearer token
        if parts[:2] != ["v2", "orders"]:
            return 404, {"error": "no such route"}
        if tenant is None:
            return 401, {"error": "unauthorized"}

        # --- collection -----------------------------------------------------------
        if parts == ["v2", "orders"]:
            if method == "GET":
                return 200, {"data": {"tenant": tenant, "orders": self.store.list_for(tenant)}}
            if method == "POST":
                pax = int(body.get("pax") or 1)
                amount = _money(body, "amount", "quote_total", default=0.0)
                order_id = self.store.create(tenant, pax, amount)
                return 201, {"data": {"order": {"id": order_id, "tenant": tenant}}}

        if len(parts) < 3:
            return 404, {"error": "no such route"}
        order_id = parts[2]

        # --- a single order.  Note: no tenant comparison.  That is the bug. --------
        if len(parts) == 3 and method == "GET":
            order = self.store.get(order_id)
            if order is None:
                return 404, {"error": "not found"}
            return 200, {
                "data": {"order": {"id": order_id, **{k: v for k, v in order.items() if k != "id"}}},
                "meta": {"served_by": "orders-api-7", "trace": str(uuid.uuid4())[:8]},
            }

        if len(parts) < 4:
            return 404, {"error": "no such route"}
        action = parts[3]

        if method == "GET" and action == "statement":
            order = self.store.get(order_id)
            if order is None:
                return 404, {"error": "not found"}
            return 200, {
                "data": {
                    "status": order["status"],
                    "quote_total": order["quote_total"],
                    "final_total": order["final_total"],
                    "pax": order["pax"],
                    "settlements": order["settlements"],
                    "reversals": order["reversals"],
                }
            }

        if method != "POST":
            return 405, {"error": "method not allowed"}

        if action == "settle":
            amount = _money(body, "value", "amount", default=0.0)

            def _settle(o: dict[str, Any]) -> None:
                o["settlements"].append({"value": amount, "state": "settled"})
                o["status"] = "PAID"

            return 200, {"data": {"order": self.store.mutate(order_id, _settle) or {}}}

        if action == "confirm":
            def _confirm(o: dict[str, Any]) -> None:
                # No check that a settlement exists.  That is the bug.
                o["status"] = "CONFIRMED"

            order = self.store.mutate(order_id, _confirm)
            if order is None:
                return 404, {"error": "not found"}
            return 200, {"data": {"order": order}}

        if action == "cancel":
            def _cancel(o: dict[str, Any]) -> None:
                o["status"] = "CANCELLED"

            order = self.store.mutate(order_id, _cancel)
            if order is None:
                return 404, {"error": "not found"}
            return 200, {"data": {"order": order}}

        if action == "refund":
            amount = _money(body, "value", "amount", default=0.0)

            def _refund(o: dict[str, Any]) -> None:
                # No idempotency, no state guard: refund twice, get paid twice.
                o["reversals"].append({"value": amount, "state": "settled"})
                o["status"] = "REFUNDED"

            order = self.store.mutate(order_id, _refund)
            if order is None:
                return 404, {"error": "not found"}
            return 200, {"data": {"order": order}}

        if action == "reprice":
            total = _money(body, "total", "amount", default=0.0)

            def _reprice(o: dict[str, Any]) -> None:
                # Client-controlled money.  That is the bug.
                o["final_total"] = total

            order = self.store.mutate(order_id, _reprice)
            if order is None:
                return 404, {"error": "not found"}
            return 200, {"data": {"order": order}}

        return 404, {"error": "no such action"}


class Handler(BaseHTTPRequestHandler):
    server_version = "OrdersAPI/2.0"
    protocol_version = "HTTP/1.1"
    api: Api = None  # type: ignore[assignment]
    verbose: bool = False

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    # -- plumbing -------------------------------------------------------------------
    def _tenant(self) -> str | None:
        header = self.headers.get("Authorization") or ""
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        return TOKENS.get(token)

    def _dispatch(self, method: str) -> None:
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body: dict[str, Any] = {}
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
                body = parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                body = {}
        status, payload = self.api.handle(method, parts.path, body, self._tenant())
        blob = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)
        if self.verbose:
            print(f"{method} {parts.path} -> {status}", file=sys.stderr)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
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
    ap = argparse.ArgumentParser(description="Second vulnerable target: /v2 orders API (local only)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("TARGET2_PORT", "8081")))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1") and os.environ.get("ALLOW_UNSAFE_BIND") != "1":
        print("refusing to bind a deliberately vulnerable app to a non-loopback address", file=sys.stderr)
        return 2

    server = make_server(args.port, args.host, args.verbose)
    print(f"target2 listening on http://{args.host}:{server.server_address[1]}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
