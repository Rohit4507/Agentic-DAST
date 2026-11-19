"""Record the mock target's normal user journeys as HAR files.

    python -m target.capture                # writes captures/agency_a.har, agency_b.har

Stands in for the provided input *"sample recorded traffic (HAR files or proxy logs)
from normal user journeys"*. Everything goes through the scope-checked client, so even
the recorder cannot leave scope -- which is the behaviour we want from every component,
not just the scanners.

On a real target, swap :func:`dast.record.journey.record_with_playwright` in here and
log in as each role through the UI.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from dast.auth import TokenStore
from dast.audit import AuditLog
from dast.http import Client
from dast.record.journey import Step, record_journey
from dast.scope import ScopeConfig, ScopeGuard


def journeys() -> dict[str, list[Step]]:
    return {
        # Agency A: browse and inspect its own bookings
        "agency_a": [
            Step("GET", "/api/bookings"),
            Step("GET", "/api/booking/8842"),
            Step("GET", "/api/ledger/8842"),
            Step("GET", "/api/booking/8843"),
        ],
        # Agency B: browse, then actually book and pay for a trip
        "agency_b": [
            Step("GET", "/api/bookings"),
            Step("GET", "/api/booking/9101"),
            Step("GET", "/api/ledger/9101"),
            Step("POST", "/api/hold", {"pax": 1, "amount": 22000.0}),
            Step("GET", "/api/bookings"),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Record mock-target journeys into HAR files")
    ap.add_argument("--scope", default="scope.json")
    ap.add_argument("--out", default="captures")
    args = ap.parse_args(argv)

    cfg = ScopeConfig.load(args.scope)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(out / "_capture_audit.jsonl")
    guard = ScopeGuard(cfg)
    tokens = TokenStore(dict(cfg.accounts))
    client = Client(guard, audit, tokens, component="recorder")

    for role, steps in journeys().items():
        path = record_journey(client, role=role, steps=steps, out_path=out / f"{role}.har")
        print(f"{role:10s} -> {path}  ({len(steps)} requests)")

    # A second hold for agency B, so the journey data includes a booking created by this run.
    hold = client.post("/api/hold", role="agency_b", json={"pax": 2, "amount": 31000.0},
                       component="recorder", note="journey:agency_b")
    if hold.status < 400:
        bid = hold.json().get("bookingId")
        client.post("/api/pay", role="agency_b", json={"booking": bid, "amount": 31000.0},
                    component="recorder", note="journey:agency_b")
        print(f"agency_b   -> hold {bid} + pay")
        # re-record so the HAR includes those two calls
        steps = journeys()["agency_b"] + [
            Step("GET", "/api/bookings"),
        ]
        record_journey(client, role="agency_b", steps=steps, out_path=out / "agency_b.har")

    print(f"\n{guard.stats.sent} requests sent, {guard.stats.checked} checked, {guard.stats.denied} refused")
    print(f"audit -> {audit.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
