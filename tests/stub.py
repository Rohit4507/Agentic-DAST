"""Shared test helpers: a stub HTTP client and a temp scope builder."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dast.http import Response


class StubClient:
    """Minimal stand-in for :class:`dast.http.Client`.

    Routes are keyed by ``(path, role)``; anything else 404s. Used to assert what the
    verifier does when a response is *not* proof of a bug.
    """

    def __init__(self, routes: dict[tuple[str, str | None], tuple[int, Any]]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str | None]] = []

    def get(self, path: str, *, role: str | None = None, component: str = "", note: str = "") -> Response:
        self.calls.append((path, role))
        status, body = self.routes.get((path, role), (404, {"error": "not found"}))
        blob = json.dumps(body).encode() if not isinstance(body, bytes) else body
        return Response(
            method="GET",
            url=f"http://stub{path}",
            status=status,
            headers={"Content-Type": "application/json"},
            body=blob,
            elapsed_ms=1.0,
        )

    def post(self, path: str, *, role: str | None = None, json: Any = None, **kw: Any) -> Response:
        return self.get(path, role=role, **kw)

    def request(self, method: str, path: str, **kw: Any) -> Response:
        return self.get(path, **kw)


def scope_mapping(base_url: str, *, budget: int = 200, kill_file: str = "/tmp/dast-test-KILL") -> dict:
    """A scope document shaped like scope.json, pointed at a test server."""
    return {
        "name": "test-engagement",
        "base_url": base_url,
        "allow_hosts": ["127.0.0.1"],
        "allow_methods": ["GET", "POST"],
        "allow_paths": [
            "/healthz",
            "/api/bookings",
            "/api/booking",
            "/api/ledger",
            "/api/hold",
            "/api/pay",
            "/api/confirm",
            "/api/cancel",
            "/api/refund",
            "/api/rebook",
            "/api/v1",
            "/api/old",
            "/api/internal",
            "/api/test/debug",
        ],
        "deny_paths": ["/api/refund/bulk"],
        "max_rps_per_host": 50,
        "max_burst": 50,
        "max_total_requests": budget,
        "max_wait_seconds": 5,
        "accounts": {"agency_a": "literal:tok-agency-a", "agency_b": "literal:tok-agency-b"},
        "role_agencies": {"agency_a": "AGENCY-A", "agency_b": "AGENCY-B"},
        "kill_switch_file": kill_file,
        "traffic_window_days": 30,
        "js_bundles": ["target/static/app.js"],
        "assets_file": "assets.json",
    }


def write_scope(path: Path, base_url: str, **kw: Any) -> Path:
    path.write_text(json.dumps(scope_mapping(base_url, **kw), indent=2), encoding="utf-8")
    return path
