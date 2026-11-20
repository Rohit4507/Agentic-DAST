"""Dotted-path field resolution.

Every place this tool has to pull a value out of a JSON body -- an object's identity,
a tenant boundary, an agency id, a ledger amount -- goes through here.  That matters
because *which key holds the value* is a property of the target, not of the scanner:
the bundled mock returns ``{"bookingId": "8842"}`` while an ordinary API returns
``{"data": {"order": {"id": "8842"}}}``.  Hard-coding the first shape is how a DAST
tool silently reports "no findings" against a real platform.

Resolution never guesses inside a *proof*.  If a path does not resolve, ``dig``
returns the default and the caller is expected to treat that as "cannot prove it" --
which, per :mod:`dast.verify.engine`, means no finding rather than a speculative one.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

_MISS = object()


def dig(payload: Any, path: str, default: Any = None) -> Any:
    """Resolve ``a.b.0.c`` inside ``payload``, returning ``default`` on any miss.

    Accepts dict keys and integer list indexes.  An empty path returns the payload
    itself, which lets a profile say "the body *is* the ledger".
    """
    if not path:
        return payload
    node = payload
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(node, Mapping):
            if part not in node:
                return default
            node = node[part]
            continue
        if isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return default
            continue
        return default
    return node


def first(payload: Any, paths: Iterable[str], default: Any = None) -> Any:
    """First path that resolves to a non-empty value.

    Empty string and ``None`` count as absent; ``0`` and ``False`` do not, because a
    real ledger legitimately has ``amount: 0`` and a tenant id of ``0`` is a value.
    """
    for path in paths:
        if not path:
            continue
        value = dig(payload, path, _MISS)
        if value is _MISS or value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return default


def where(payload: Any, paths: Iterable[str]) -> str:
    """Which of ``paths`` resolved -- for reports, so a human can audit the parse."""
    for path in paths:
        if dig(payload, path, _MISS) is not _MISS:
            return path
    return ""


def as_float(value: Any, default: float = 0.0) -> float:
    """Money arrives as a number, a numeric string, or a formatted string."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().replace(",", "").replace("_", "")
        for symbol in ("INR", "USD", "Rs", "Rs.", "\u20b9", "$"):
            cleaned = cleaned.replace(symbol, "")
        try:
            return float(cleaned.strip())
        except ValueError:
            return default
    return default


def as_int(value: Any, default: int = 0) -> int:
    return int(as_float(value, float(default)))


def as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def rows(value: Any) -> list[dict[str, Any]]:
    """A list-of-objects field, tolerating a single object or a wrapped list."""
    if isinstance(value, Mapping):
        return [dict(value)]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    return []


def identity_of(payload: Any, candidates: Sequence[str]) -> tuple[str, Any]:
    """``(path, value)`` for the first candidate that resolves, else ``("", None)``."""
    for path in candidates:
        value = dig(payload, path, _MISS)
        if value is _MISS or value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return path, value
    return "", None


#: Names an API uses for "this object's id".
ID_NAMES: tuple[str, ...] = ("id", "bookingId", "booking_id", "orderId", "order_id", "uuid", "_id")


def variants(path: str, names: Sequence[str] = ID_NAMES) -> tuple[str, ...]:
    """Re-spell the *last* segment of a dotted path.

    ``data.order.id`` -> ``data.order.order_id``, ``data.order.uuid``, ...
    so a response that renames one key does not read as a fixed vulnerability.
    """
    head, _, _last = path.rpartition(".")
    out: list[str] = [path] if path else []
    for name in names:
        candidate = f"{head}.{name}" if head else name
        if candidate not in out:
            out.append(candidate)
    return tuple(out)


def same(a: Any, b: Any) -> bool:
    """Identity comparison that tolerates ``8842`` vs ``"8842"`` and UUID case."""
    if a is None or b is None:
        return False
    return str(a).strip().lower() == str(b).strip().lower()
