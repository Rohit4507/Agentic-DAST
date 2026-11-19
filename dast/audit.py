"""Append-only, tamper-evident audit log.

Rules of Engagement: *"Log every request so reviewers can replay what the agent did."*

Each line is one JSON object with a hash chain (``prev_hash`` -> ``entry_hash``), so
truncation or editing of a middle line is detectable — :func:`verify_chain` returns
the first broken sequence number. Secrets never enter the log: authorization headers
and token-shaped query values are replaced at write time.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

GENESIS = "0" * 64

_SECRET_QUERY_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "passwd",
    "sig",
    "signature",
    "session",
    "sessionid",
    "auth",
    "code",
}
_SECRET_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "x-csrf-token",
}

_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/=]{4,}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable>"
    if not parts.query:
        return url
    kept = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if k.lower() in _SECRET_QUERY_KEYS:
            kept.append((k, "<redacted>"))
        else:
            kept.append((k, v))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), ""))


def redact_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        if k.lower() in _SECRET_HEADER_KEYS:
            out[k] = "<redacted>"
        else:
            out[k] = _BEARER_RE.sub(lambda m: f"{m.group(1)} <redacted>", str(v))
    return out


def redact_text(text: str) -> str:
    return _BEARER_RE.sub(lambda m: f"{m.group(1)} <redacted>", text or "")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(obj: Any) -> str:
    if isinstance(obj, bytes):
        return sha256_bytes(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _entry_hash(entry: Mapping[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


class AuditLog:
    """Thread-safe append-only JSONL writer with a hash chain."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._prev = self._resume()

    def _resume(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)
                    except json.JSONDecodeError:
                        continue
        if not last:
            return 0, GENESIS
        return int(last.get("seq", 0)), str(last.get("entry_hash", GENESIS))

    # -- writes ---------------------------------------------------------------------

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            entry: dict[str, Any] = {
                "seq": self._seq,
                "ts": now_iso(),
                "event": event,
                "prev_hash": self._prev,
            }
            for k, v in fields.items():
                entry[k] = _sanitize(k, _strip(v))
            entry["entry_hash"] = _entry_hash(entry)
            self._prev = entry["entry_hash"]
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:  # pragma: no cover - fsync unsupported on some FS
                    pass
            return entry

    def request(self, **fields: Any) -> dict[str, Any]:
        return self.write("request", **fields)

    def denied(self, **fields: Any) -> dict[str, Any]:
        return self.write("denied", **fields)

    def note(self, **fields: Any) -> dict[str, Any]:
        return self.write("note", **fields)

    # -- reads ----------------------------------------------------------------------

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter_entries(self.path)

    def count(self, event: str | None = None) -> int:
        return sum(1 for e in self if event is None or e.get("event") == event)


_URL_FIELDS = {"url", "path", "endpoint", "target", "uri"}
_HEADER_FIELDS = {"request_headers", "headers", "response_headers"}


def _sanitize(key: str, value: Any) -> Any:
    """Redact at the *writer*, not only at the caller.

    Redaction used to live entirely in :class:`~dast.http.Client`, which meant any
    other caller of ``audit.request(...)`` could write a secret to disk. Defence in
    depth: the log itself refuses to store credentials, whatever the caller passes.
    """
    lk = key.lower()
    if isinstance(value, str):
        if lk in _URL_FIELDS:
            return redact_url(value)
        return redact_text(value)
    if isinstance(value, Mapping):
        if lk in _HEADER_FIELDS:
            return redact_headers({str(k): str(v) for k, v in value.items()})
        return {k: _sanitize(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(key, item) for item in value]
    return value


def _strip(value: Any) -> Any:
    """Remove non-serialisable / huge values before they hit disk."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return {"sha256": sha256_bytes(value), "len": len(value)}
    if isinstance(value, Mapping):
        return {str(k): _strip(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strip(v) for v in value]
    return str(value)


def iter_entries(path: str | Path) -> Iterator[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                yield {"event": "corrupt", "raw": line}


def audit_head(path: str | Path) -> tuple[int, str]:
    """``(last_seq, last_entry_hash)`` -- the value to record elsewhere.

    A hash chain alone cannot detect truncation: dropping the last N lines leaves a
    valid prefix. Publishing the head (in the report and in ``findings.json``) anchors
    it, so :func:`verify_chain` can then prove the log is complete as well as unedited.
    """
    last_seq, last_hash = 0, GENESIS
    for entry in iter_entries(path):
        if entry.get("event") == "corrupt":
            continue
        last_seq = int(entry.get("seq", last_seq) or last_seq)
        last_hash = str(entry.get("entry_hash", last_hash) or last_hash)
    return last_seq, last_hash


def verify_chain(path: str | Path, expect_head: tuple[int, str] | None = None) -> tuple[bool, int | None, str]:
    """Return ``(ok, first_bad_seq, reason)``.

    With ``expect_head`` the log must also end exactly at the recorded head, which is
    what makes tail truncation detectable.
    """
    prev = GENESIS
    expected_seq = 1
    last_seq, last_hash = 0, GENESIS
    for entry in iter_entries(path):
        if entry.get("event") == "corrupt":
            return False, expected_seq, "unparseable line"
        if entry.get("seq") != expected_seq:
            return False, expected_seq, f"sequence gap: saw {entry.get('seq')}"
        if entry.get("prev_hash") != prev:
            return False, expected_seq, "prev_hash mismatch (line removed or reordered)"
        if entry.get("entry_hash") != _entry_hash(entry):
            return False, expected_seq, "entry_hash mismatch (line edited)"
        prev = entry["entry_hash"]
        last_seq, last_hash = entry["seq"], entry["entry_hash"]
        expected_seq += 1
    if expect_head is not None and (last_seq, last_hash) != tuple(expect_head):
        return (
            False,
            last_seq + 1,
            f"log does not end at the recorded head ({last_seq}/{last_hash[:12]} "
            f"!= {expect_head[0]}/{str(expect_head[1])[:12]}): truncated",
        )
    return True, None, "chain intact"
