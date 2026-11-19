"""HAR (HTTP Archive) reading and writing.

The participant pack lists *"sample recorded traffic (HAR files or proxy logs) from
normal user journeys"* as a provided input, so this module is the front door to the
inventory: it turns captures into :class:`~dast.model.TrafficHit` rows.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit

from ..model import TrafficHit, parse_iso, utcnow

_AUTH_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token"}


def read_har(path: str | Path, *, role: str = "", source: str = "har") -> list[TrafficHit]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    return parse_har(data, role=role or p.stem, source=source)


def parse_har(data: dict[str, Any], *, role: str = "", source: str = "har") -> list[TrafficHit]:
    entries = (data.get("log") or {}).get("entries") or []
    hits: list[TrafficHit] = []
    for entry in entries:
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = req.get("url") or ""
        if not url:
            continue
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            continue
        headers = {str(h.get("name", "")).lower() for h in (req.get("headers") or [])}
        keys = _json_keys((resp.get("content") or {}).get("text"))
        hits.append(
            TrafficHit.build(
                method=req.get("method", "GET"),
                path=parts.path or "/",
                status=int(resp.get("status") or 0),
                ts=parse_iso(entry.get("startedDateTime", "")) or utcnow(),
                role=role,
                source=source,
                response_keys=keys,
                auth_present=bool(headers & _AUTH_HEADERS),
                query_keys=[k for k, _ in parse_qsl(parts.query)],
            )
        )
    return hits


def _json_keys(text: Any) -> list[str]:
    if not isinstance(text, str) or not text.strip():
        return []
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    return sorted(_walk_keys(obj))


def _walk_keys(obj: Any, depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > 3:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k))
            out |= _walk_keys(v, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:5]:
            out |= _walk_keys(item, depth + 1)
    return out


# --------------------------------------------------------------------------------------
# writing (used by the mock target's journey recorder)
# --------------------------------------------------------------------------------------


def entry_from_exchange(
    *,
    method: str,
    url: str,
    request_headers: dict[str, str],
    status: int,
    response_text: str,
    started: Any = None,
    elapsed_ms: float = 0.0,
) -> dict[str, Any]:
    from ..model import iso

    return {
        "startedDateTime": iso(started or utcnow()),
        "time": round(elapsed_ms, 2),
        "request": {
            "method": method.upper(),
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in request_headers.items()],
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": status,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"size": len(response_text), "mimeType": "application/json", "text": response_text},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(response_text),
        },
        "cache": {},
        "timings": {"send": 0, "wait": round(elapsed_ms, 2), "receive": 0},
    }


def write_har(path: str | Path, entries: Iterable[dict[str, Any]], *, creator: str = "dast-agent") -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "log": {
            "version": "1.2",
            "creator": {"name": creator, "version": "0.1"},
            "entries": list(entries),
        }
    }
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return p


def merge_hits(hits: Iterable[TrafficHit]) -> dict[str, list[TrafficHit]]:
    """Group hits by ``METHOD template``."""
    grouped: dict[str, list[TrafficHit]] = {}
    for h in hits:
        grouped.setdefault(f"{h.method} {h.template}", []).append(h)
    return grouped
