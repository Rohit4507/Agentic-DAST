"""Generate a synthetic 30-day API-gateway access log for the mock target.

    python -m target.make_traffic

Stands in for the provided input *"API gateway and load balancer access logs for the
last 30 to 90 days"*. The important property: it lists the routes that real users hit
(with plausible timestamps), and it omits the routes that nobody calls. That omission
is what turns /api/v1, /api/old and /api/test into zombies.

Output: target/traffic/gateway_30d.jsonl
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent / "traffic" / "gateway_30d.jsonl"

# (method, path, weight) -- weight ~ how often a normal day hits it
ACTIVE = [
    ("GET", "/api/bookings", 18),
    ("GET", "/api/booking/8842", 9),
    ("GET", "/api/booking/8843", 7),
    ("GET", "/api/booking/9101", 6),
    ("GET", "/api/ledger/8842", 4),
    ("GET", "/api/ledger/8843", 3),
    ("GET", "/api/ledger/9101", 3),
    ("POST", "/api/hold", 4),
    ("POST", "/api/pay", 4),
    ("POST", "/api/confirm", 3),
    ("POST", "/api/cancel", 2),
    ("POST", "/api/refund", 2),
    ("POST", "/api/rebook", 1),
]

# in use by an internal tool, documented nowhere -> shadow
SHADOW = [
    ("GET", "/api/internal/agency/AGENCY-A/export", 1),
]


def main() -> int:
    rng = random.Random(20261119)  # deterministic fixture
    now = datetime.now(timezone.utc).replace(microsecond=0)
    rows: list[dict[str, object]] = []

    for day in range(30, 0, -1):
        for _ in range(rng.randint(14, 26)):
            method, path, _weight = rng.choices(ACTIVE, weights=[w for _, _, w in ACTIVE], k=1)[0]
            ts = now - timedelta(days=day, hours=rng.uniform(0, 23), minutes=rng.uniform(0, 59))
            rows.append(
                {
                    "ts": ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
                    "method": method,
                    "path": path,
                    "status": rng.choice([200, 200, 200, 201, 200, 404]) if method == "POST" else 200,
                    "source": "gateway",
                }
            )

    # the shadow consumer: a handful of hits, the most recent 12 days ago
    for days_ago, count in ((28, 2), (19, 1), (12, 3)):
        for i in range(count):
            ts = now - timedelta(days=days_ago, hours=2 + i)
            method, path, _ = SHADOW[0]
            rows.append(
                {
                    "ts": ts.isoformat(timespec="seconds").replace("+00:00", "Z"),
                    "method": method,
                    "path": path,
                    "status": 200,
                    "source": "gateway",
                }
            )

    rows.sort(key=lambda r: str(r["ts"]))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    print(f"{len(rows)} log lines -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
