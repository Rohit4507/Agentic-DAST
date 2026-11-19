"""Real-traffic correlation.

Zombie/shadow labelling needs a *second* source besides the live crawl: the gateway or
load-balancer access log for the last 30-90 days (provided input per the pack). This
module reads those logs in the two shapes they usually arrive in — JSONL and
combined-log-style text — and reduces them to ``route -> last seen``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from ..model import TrafficHit, parse_iso, template_of

# 127.0.0.1 - - [19/Nov/2026:10:22:01 +0000] "GET /api/booking/8842 HTTP/1.1" 200 421 12ms
_COMBINED = re.compile(
    r'\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})'
)


def read_gateway_log(path: str | Path, *, source: str = "gateway") -> list[TrafficHit]:
    p = Path(path)
    if not p.exists():
        return []
    text = p.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return _parse_jsonl(text, source)
    return _parse_combined(text, source)


def _parse_jsonl(text: str, source: str) -> list[TrafficHit]:
    hits: list[TrafficHit] = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        path = row.get("path") or row.get("url") or ""
        if isinstance(path, str) and path.startswith("http"):
            from urllib.parse import urlsplit

            path = urlsplit(path).path
        ts = parse_iso(str(row.get("ts") or row.get("timestamp") or row.get("time") or ""))
        if not path or ts is None:
            continue
        hits.append(
            TrafficHit.build(
                method=str(row.get("method", "GET")),
                path=str(path),
                status=int(row.get("status") or 0),
                ts=ts,
                role=str(row.get("role") or row.get("agency") or ""),
                source=source,
            )
        )
    return hits


def _parse_combined(text: str, source: str) -> list[TrafficHit]:
    from datetime import datetime

    hits: list[TrafficHit] = []
    for line in text.splitlines():
        m = _COMBINED.search(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        hits.append(
            TrafficHit.build(
                method=m.group("method"),
                path=m.group("path").split("?")[0],
                status=int(m.group("status")),
                ts=ts,
                source=source,
            )
        )
    return hits


def aggregate_traffic(hits: Iterable[TrafficHit]) -> dict[str, dict[str, Any]]:
    """``METHOD template -> {last_seen, count, roles, statuses}``."""
    agg: dict[str, dict[str, Any]] = {}
    for h in hits:
        key = f"{h.method} {h.template}"
        cur = agg.setdefault(
            key,
            {"last_seen": None, "count": 0, "roles": set(), "statuses": set(), "template": h.template,
             "method": h.method, "sample_path": h.path},
        )
        cur["count"] += 1
        cur["statuses"].add(h.status)
        if h.role:
            cur["roles"].add(h.role)
        if cur["last_seen"] is None or h.ts > cur["last_seen"]:
            cur["last_seen"] = h.ts
            cur["sample_path"] = h.path
    for v in agg.values():
        v["roles"] = sorted(v["roles"])
        v["statuses"] = sorted(v["statuses"])
    return agg


def load_asset_map(path: str | Path) -> dict[str, str]:
    """Asset ownership: ``{"path_prefix": "owner team"}`` (provided input)."""
    p = Path(path)
    if not p or not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if isinstance(data, dict) and "owners" in data:
        data = data["owners"]
    return {str(k): str(v) for k, v in (data or {}).items()}


def owner_for(template: str, asset_map: dict[str, str]) -> str:
    best, best_len = "unassigned", -1
    for prefix, owner in asset_map.items():
        if template.startswith(prefix) and len(prefix) > best_len:
            best, best_len = owner, len(prefix)
    return best
