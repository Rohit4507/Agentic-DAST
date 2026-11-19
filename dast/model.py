"""Shared data model.

The vocabulary here is the hackathon's: an endpoint is ``active``, ``zombie`` or
``shadow``, and every inventory row carries the fields the participant pack asks for
(last real traffic, auth reachability, data exposed, owner, recommendation).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

ACTIVE, ZOMBIE, SHADOW, UNKNOWN = "active", "zombie", "shadow", "unknown"

_DIGITS = re.compile(r"^\d{1,20}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TOKENISH = re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{4,64}$")

#: response keys that mean a data class is exposed
PII_KEYS = {"passport", "email", "phone", "name", "dob", "address", "traveller", "pax", "paxdetails"}
FINANCIAL_KEYS = {"amount", "finalamount", "quotedamount", "refund", "refunds", "payments", "paid", "price",
                  "fare", "card", "totalvalue", "bookingcount", "revenue", "credit"}
INTERNAL_KEYS = {"env", "python", "featureflags", "internal", "debug", "stack", "version"}
_AUTH_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(text: str) -> datetime | None:
    if not text:
        return None
    t = text.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(t, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def template_of(path: str) -> tuple[str, list[str]]:
    """``/api/booking/8842`` -> ``("/api/booking/{id}", ["8842"])``."""
    path = (path or "/").split("?", 1)[0].split("#", 1)[0]
    ids: list[str] = []
    out: list[str] = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
            continue
        if _DIGITS.match(seg) or _UUID.match(seg) or _TOKENISH.match(seg):
            ids.append(seg)
            out.append("{id}")
        else:
            out.append(seg)
    tpl = "/".join(out)
    return (tpl if tpl.startswith("/") else "/" + tpl), ids


def route_key(method: str, template: str) -> str:
    return f"{method.upper()} {template}"


@dataclass
class TrafficHit:
    """One observed request, from a HAR or a gateway log."""

    method: str
    path: str
    template: str
    status: int
    ts: datetime
    role: str = ""
    source: str = "har"
    object_ids: list[str] = field(default_factory=list)
    response_keys: list[str] = field(default_factory=list)
    auth_present: bool = False
    query_keys: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, *, method: str, path: str, status: int, ts: datetime, role: str = "",
              source: str = "har", response_keys: list[str] | None = None,
              auth_present: bool = False, query_keys: list[str] | None = None) -> "TrafficHit":
        tpl, ids = template_of(path)
        return cls(
            method=method.upper(),
            path=path,
            template=tpl,
            status=status,
            ts=ts,
            role=role,
            source=source,
            object_ids=ids,
            response_keys=sorted({k.lower() for k in (response_keys or [])}),
            auth_present=auth_present,
            query_keys=sorted(query_keys or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "template": self.template,
            "status": self.status,
            "ts": iso(self.ts),
            "role": self.role,
            "source": self.source,
            "object_ids": self.object_ids,
            "response_keys": self.response_keys,
            "auth_present": self.auth_present,
        }


@dataclass
class Probe:
    reachable: bool | None = None
    status: int | None = None
    auth_required: bool | None = None
    data_classes: list[str] = field(default_factory=list)
    response_keys: list[str] = field(default_factory=list)
    error: str = ""
    attempted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "reachable": self.reachable,
            "status": self.status,
            "auth_required": self.auth_required,
            "data_classes": self.data_classes,
            "response_keys": self.response_keys[:40],
            "error": self.error,
        }


@dataclass
class EndpointRecord:
    """One row of the inventory. Field names follow the participant pack."""

    method: str
    template: str
    label: str = UNKNOWN
    sample_path: str = ""
    roles_seen: list[str] = field(default_factory=list)
    hit_count: int = 0
    last_seen: datetime | None = None
    in_traffic: bool = False
    in_js: bool = False
    in_declared: bool = False
    probe: Probe = field(default_factory=Probe)
    owner: str = "unassigned"
    recommendation: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return route_key(self.method, self.template)

    @property
    def data_classes(self) -> list[str]:
        return list(self.probe.data_classes)

    def age_days(self, now: datetime | None = None) -> float | None:
        if self.last_seen is None:
            return None
        return round(((now or utcnow()) - self.last_seen).total_seconds() / 86400.0, 2)

    def to_dict(self, now: datetime | None = None) -> dict[str, Any]:
        age = self.age_days(now)
        return {
            "method": self.method,
            "path_template": self.template,
            "label": self.label,
            "last_seen_real_traffic": iso(self.last_seen) if self.last_seen else None,
            "days_since_real_traffic": age,
            "reachable_without_auth": (
                None if self.probe.auth_required is None else (not self.probe.auth_required)
            ),
            "reachable": self.probe.reachable,
            "http_status_on_probe": self.probe.status,
            "data_exposed": self.probe.data_classes,
            "response_keys": self.probe.response_keys[:40],
            "roles_observed": self.roles_seen,
            "hit_count": self.hit_count,
            "in_js_bundle": self.in_js,
            "in_declared_spec": self.in_declared,
            "in_traffic": self.in_traffic,
            "owner": self.owner,
            "recommendation": self.recommendation,
            "notes": self.notes,
        }


def deep_keys(obj: Any, depth: int = 0, limit: int = 4) -> list[str]:
    """All keys in a JSON structure, lowercased, de-duplicated.

    Top-level-only inspection misses the interesting case: a wrapper object whose only
    sensitive content is nested (``{"bookings": [{"traveller": {...}}]}``).
    """
    out: set[str] = set()

    def walk(node: Any, d: int) -> None:
        if d > limit:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                out.add(str(k).lower())
                walk(v, d + 1)
        elif isinstance(node, list):
            for item in node[:5]:
                walk(item, d + 1)

    walk(obj, depth)
    return sorted(out)


def classify_data(keys: list[str]) -> list[str]:
    k = {x.lower() for x in keys}
    classes: list[str] = []
    if k & PII_KEYS:
        classes.append("PII")
    if k & FINANCIAL_KEYS:
        classes.append("financial")
    if k & INTERNAL_KEYS:
        classes.append("internal-config")
    return classes


@dataclass
class Evidence:
    """Minimum-evidence slice. Long bodies are truncated and PII masked, by policy."""

    request: dict[str, Any]
    response: dict[str, Any]
    extracted: dict[str, Any] = field(default_factory=dict)
    redactions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request,
            "response": self.response,
            "extracted": self.extracted,
            "redactions": self.redactions,
        }


@dataclass
class Finding:
    id: str
    title: str
    vuln_class: str
    endpoint: str
    method: str
    severity: str = "informational"
    cvss: float = 0.0
    business_impact: str = ""
    confidence: str = "candidate"
    owner: str = "unassigned"
    owasp: str = ""
    cwe: str = ""
    evidence: Evidence | None = None
    impact: str = ""
    remediation: str = ""
    retest: dict[str, Any] = field(default_factory=dict)
    proof_hash: str = ""
    dedupe_key: str = ""
    notes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "method": self.method,
            "severity": self.severity,
            "cvss": self.cvss,
            "business_impact": self.business_impact,
            "confidence": self.confidence,
            "owner": self.owner,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "retest": self.retest,
            "proof_hash": self.proof_hash,
            "dedupe_key": self.dedupe_key,
            "notes": self.notes,
            "created_at": iso(self.created_at),
        }


def window_start(days: int) -> datetime:
    return utcnow() - timedelta(days=days)
