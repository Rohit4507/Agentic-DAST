"""Generate target2's "provided inputs": HAR captures and a 30-day gateway log.

The participant pack promises real traffic; these fixtures are that promise in
miniature, in the two shapes a real engagement actually hands over:

* ``captures/<role>.har`` -- one HAR per authenticated role, so object ids and the
  role that owns them are known before a single request is sent.
* ``traffic/gateway_30d.jsonl`` -- gateway JSONL, which is what makes a route
  "active" and lets an undocumented route show up as *shadow*.

They are generated rather than committed with hard-coded dates so that a run six
months from now does not silently classify the whole API as zombie.  Run it directly
to refresh the copies under ``target2/``:

    python -m target2.fixtures --out target2
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ORDER_A = "8f14e45f-ceea-467f-a1b2-1c9e2d3f4a01"
ORDER_B = "8f14e45f-ceea-467f-a1b2-1c9e2d3f4a02"

TENANT_A = "TN-A"
TENANT_B = "TN-B"


def _order_body(order_id: str, tenant: str) -> dict[str, Any]:
    return {
        "data": {
            "order": {
                "id": order_id,
                "tenant": tenant,
                "status": "HELD",
                "quote_total": 4800.0,
                "final_total": 4800.0,
                "pax": 2,
                "customer": {
                    "name": "Traveller",
                    "email": "traveller@example-agency.test",
                    "phone": "+91-90000-00001",
                    "passport": "P1234567",
                },
            },
            "tenant": tenant,
        },
        "meta": {"served_by": "orders-api-7"},
    }


def _entry(ts: datetime, url: str, status: int, body: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(body)
    return {
        "startedDateTime": ts.isoformat().replace("+00:00", "Z"),
        "time": 12,
        "request": {
            "method": "GET",
            "url": url,
            "headers": [{"name": "Authorization", "value": "Bearer captured"}],
        },
        "response": {
            "status": status,
            "content": {"mimeType": "application/json", "text": text, "size": len(text)},
        },
    }


def write_har(path: Path, *, role: str, order_id: str, tenant: str, base: str, now: datetime) -> Path:
    entries = [
        _entry(now - timedelta(days=2), f"{base}/v2/orders", 200,
               {"data": {"tenant": tenant, "orders": [order_id]}}),
        _entry(now - timedelta(days=2, minutes=-1), f"{base}/v2/orders/{order_id}", 200,
               _order_body(order_id, tenant)),
        _entry(now - timedelta(days=2, minutes=-2), f"{base}/v2/orders/{order_id}/statement", 200,
               {"data": {"status": "HELD", "quote_total": 4800.0, "final_total": 4800.0,
                         "settlements": [], "reversals": []}}),
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"log": {"version": "1.2", "creator": {"name": f"capture:{role}"}, "entries": entries}}, indent=2),
        encoding="utf-8",
    )
    return path


#: (method, path, status, how many times in the window)
GATEWAY_ROWS: tuple[tuple[str, str, int, int], ...] = (
    ("GET", "/v2/orders", 200, 6),
    ("GET", f"/v2/orders/{ORDER_A}", 200, 9),
    ("GET", f"/v2/orders/{ORDER_B}", 200, 5),
    ("GET", f"/v2/orders/{ORDER_A}/statement", 200, 4),
    ("POST", f"/v2/orders/{ORDER_A}/settle", 200, 3),
    ("POST", f"/v2/orders/{ORDER_A}/confirm", 200, 2),
    ("POST", f"/v2/orders/{ORDER_A}/cancel", 200, 1),
    ("POST", f"/v2/orders/{ORDER_B}/refund", 200, 1),
    ("POST", f"/v2/orders/{ORDER_B}/reprice", 200, 1),
    # Undocumented in every bundle: shows up as shadow.
    ("GET", "/v2/internal/reports", 200, 12),
    # /v2/legacy/orders/{id} is deliberately absent: it is the zombie.
)


def write_gateway(path: Path, *, now: datetime, days: int = 30) -> Path:
    rows: list[str] = []
    step = 0
    for method, row_path, status, count in GATEWAY_ROWS:
        for _ in range(count):
            step += 1
            ts = now - timedelta(days=days / 2, minutes=step * 7)
            rows.append(
                json.dumps(
                    {
                        "ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "method": method,
                        "path": row_path,
                        "status": status,
                        "source": "gateway",
                    }
                )
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def write_all(out: str | Path = "target2", *, base: str = "http://127.0.0.1:8081",
              now: datetime | None = None) -> dict[str, Path]:
    root = Path(out)
    now = now or datetime.now(timezone.utc)
    return {
        "captures": root / "captures",
        "har_a": write_har(root / "captures" / "tenant_a.har", role="tenant_a",
                           order_id=ORDER_A, tenant=TENANT_A, base=base, now=now),
        "har_b": write_har(root / "captures" / "tenant_b.har", role="tenant_b",
                           order_id=ORDER_B, tenant=TENANT_B, base=base, now=now),
        "gateway": write_gateway(root / "traffic" / "gateway_30d.jsonl", now=now),
        "bundle": root / "static" / "app.js",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate target2 captures and gateway log")
    ap.add_argument("--out", default="target2")
    ap.add_argument("--base", default="http://127.0.0.1:8081")
    args = ap.parse_args(argv)
    written = write_all(args.out, base=args.base)
    for name, path in written.items():
        print(f"{name:9s} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
