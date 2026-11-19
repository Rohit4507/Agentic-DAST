"""The three-way diff that produces the inventory.

    routes_in_js       static harvest from front-end bundles
    routes_in_traffic  HAR journeys + gateway log over the last N days
    routes_in_declared generated OpenAPI (we start with none -- no docs are provided)

    in traffic + mapped              -> active
    in JS, no real traffic, responds -> zombie   (recommendation: decommission)
    in traffic, never mapped         -> shadow   (recommendation: restrict + document)

Probing is a separate, capped, fully scope-checked step: one unauthenticated request
per candidate, plus one authenticated request only if the first said 401/403.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from ..errors import ScopeViolation, TransportError, STOPPING
from ..http import Client
from ..model import (
    ACTIVE,
    SHADOW,
    UNKNOWN,
    ZOMBIE,
    EndpointRecord,
    Probe,
    TrafficHit,
    classify_data,
    template_of,
    utcnow,
    window_start,
)
from .traffic import aggregate_traffic, owner_for


def _listed_in(template: str, routes: set[str]) -> bool:
    """Is ``template`` covered by any harvested route? Segment-aware prefix match.

    Front-end bundles rarely contain the ``{id}`` form literally, so ``/api/booking``
    must be recognised as covering ``/api/booking/{id}``.
    """
    for r in routes:
        if template == r or template.startswith(r.rstrip("/") + "/"):
            return True
    return False


def build_inventory(
    *,
    har_hits: Iterable[TrafficHit] = (),
    gateway_hits: Iterable[TrafficHit] = (),
    js_routes: Iterable[str] = (),
    declared_routes: Iterable[str] = (),
    window_days: int = 30,
    asset_map: dict[str, str] | None = None,
    now: datetime | None = None,
) -> list[EndpointRecord]:
    now = now or utcnow()
    asset_map = asset_map or {}
    js = set(js_routes)
    declared = set(declared_routes)

    har_hits = list(har_hits)
    traffic = aggregate_traffic(list(gateway_hits) + har_hits)

    roles_by_route: dict[str, set[str]] = {}
    sample_by_route: dict[str, str] = {}
    keys_by_route: dict[str, set[str]] = {}
    for h in har_hits:
        key = f"{h.method} {h.template}"
        if h.role:
            roles_by_route.setdefault(key, set()).add(h.role)
        sample_by_route.setdefault(key, h.path)
        keys_by_route.setdefault(key, set()).update(h.response_keys)

    cut = window_start(window_days)
    records: list[EndpointRecord] = []
    covered: set[str] = set()

    # -- 1. every route with observed traffic -------------------------------------
    for key in sorted(traffic):
        method, _, template = key.partition(" ")
        agg = traffic[key]
        last_seen = agg["last_seen"]
        in_traffic = bool(last_seen and last_seen >= cut)
        rec = EndpointRecord(
            method=method,
            template=template,
            in_traffic=in_traffic,
            in_js=_listed_in(template, js),
            in_declared=_listed_in(template, declared),
            hit_count=agg["count"],
            last_seen=last_seen,
            sample_path=agg["sample_path"] or sample_by_route.get(key, ""),
            roles_seen=sorted(set(agg["roles"]) if agg["roles"] else roles_by_route.get(key, set())),
        )
        rec.owner = owner_for(template, asset_map)
        _label(rec, in_traffic, now, window_days)
        records.append(rec)
        covered.add(f"{method} {template}")

    # -- 2. routes that exist only in a bundle or the generated spec --------------
    for template in sorted(js | declared):
        if any(_listed_in(r.template, {template}) and r.method == "GET" for r in records):
            continue
        if any(r.template == template for r in records):
            continue
        rec = EndpointRecord(
            method="GET",
            template=template,
            in_traffic=False,
            in_js=template in js,
            in_declared=template in declared,
            sample_path=sample_by_route.get(f"GET {template}", ""),
        )
        rec.owner = owner_for(template, asset_map)
        _label(rec, False, now, window_days)
        records.append(rec)

    return records


def _label(rec: EndpointRecord, in_traffic: bool, now: datetime, window_days: int) -> None:
    if in_traffic and (rec.in_js or rec.in_declared):
        rec.label = ACTIVE
    elif in_traffic and not rec.in_js and not rec.in_declared:
        rec.label = SHADOW
        rec.notes.append("observed in real traffic but absent from every front-end bundle and spec")
    elif (rec.in_js or rec.in_declared) and not in_traffic:
        rec.label = ZOMBIE
        age = rec.age_days(now)
        rec.notes.append(
            f"in a front-end bundle but "
            + (f"{age} days since last real traffic" if age is not None else "no real traffic on record")
            + f" (window {window_days}d)"
        )
    else:
        rec.label = UNKNOWN
    if rec.label == ZOMBIE and any(seg in rec.template for seg in ("/v1/", "/v2/", "/old/")):
        rec.notes.append("appears to be a superseded API version")


# --------------------------------------------------------------------------------------
# probing
# --------------------------------------------------------------------------------------


def _candidate_paths(rec: EndpointRecord, known_ids: list[str], limit: int = 3) -> list[str]:
    """Concrete paths to try for a template, best guess first.

    Differs identifiers because routes disagree about what ``{id}`` means: a booking id
    404s on an agency-scoped route. Trying a handful is bounded, audited exploration --
    not enumeration.
    """
    out: list[str] = []
    if rec.sample_path:
        out.append(rec.sample_path)
    for candidate in list(known_ids)[:limit] + ["1"]:
        path = "/".join(str(candidate) if seg == "{id}" else seg for seg in rec.template.split("/")) or "/"
        if path not in out:
            out.append(path)
    return out[:limit]


def _sample_path_for(rec: EndpointRecord, known_ids: list[str]) -> str:
    return _candidate_paths(rec, known_ids)[0]


def probe_candidates(
    client: Client,
    records: list[EndpointRecord],
    *,
    roles: Iterable[str] = ("agency_a",),
    known_ids: Iterable[str] = (),
    labels: Iterable[str] = (ZOMBIE, SHADOW, UNKNOWN),
    max_probes: int = 15,
) -> int:
    """Confirm liveness + auth reachability for non-active rows. Returns probes sent."""
    role_list = list(roles)
    ids = list(known_ids)
    wanted = set(labels)
    sent = 0
    for rec in records:
        if rec.label not in wanted:
            continue
        if sent >= max_probes:
            rec.notes.append("probe skipped: probe budget reached")
            continue
        probe = rec.probe
        probe.attempted = True
        anon = None
        path = ""
        try:
            for candidate_path in _candidate_paths(rec, ids):
                path = candidate_path
                anon = client.get(path, component="inventory-probe", note=f"liveness:{rec.key}")
                sent += 1
                if anon.status not in (404, 405, 410, 501):
                    break
            assert anon is not None
            rec.sample_path = path
            probe.status = anon.status
            if anon.status in (401, 403):
                probe.auth_required = True
                rec.notes.append("requires authentication")
                if role_list:
                    authed = client.get(
                        path, role=role_list[0], component="inventory-probe", note=f"liveness-authed:{rec.key}"
                    )
                    sent += 1
                    probe.reachable = authed.status < 400
                    probe.status = authed.status
                    _record_keys(probe, authed)
                else:
                    probe.reachable = True
            elif anon.status in (404, 405, 410, 501):
                probe.auth_required = None
                probe.reachable = False
                rec.notes.append(f"did not respond usefully ({anon.status})")
            else:
                probe.auth_required = False
                probe.reachable = anon.status < 400
                _record_keys(probe, anon)
        except STOPPING:
            raise  # budget spent / kill switch dropped -> stop the whole run
        except ScopeViolation as exc:
            probe.reachable = None
            probe.error = f"refused by scope guard: {exc.reason}"
            rec.notes.append(f"not probed: {probe.error}")
        except TransportError as exc:
            probe.reachable = None
            probe.error = str(exc)
            rec.notes.append("probe transport error")
        _recommend(rec)
    return sent


def _record_keys(probe: Probe, resp) -> None:
    try:
        body = resp.json()
    except ValueError:
        probe.response_keys = []
        probe.data_classes = []
        return
    keys = _keys(body)
    probe.response_keys = sorted(keys)
    probe.data_classes = classify_data(sorted(keys))


def _keys(obj: Any, depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > 3:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k))
            out |= _keys(v, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:3]:
            out |= _keys(item, depth + 1)
    return out


def _recommend(rec: EndpointRecord) -> None:
    if rec.label == ACTIVE:
        rec.recommendation = "none"
        return
    classes = ", ".join(rec.probe.data_classes) or "no sensitive data observed"
    unauth = rec.probe.auth_required is False
    if rec.label == ZOMBIE:
        if rec.probe.reachable is False:
            rec.recommendation = "verify then decommission (no usable response)"
        elif unauth and rec.probe.data_classes:
            rec.recommendation = f"decommission immediately — unauthenticated {classes} exposure"
        elif unauth:
            rec.recommendation = "restrict (require auth), then decommission"
        else:
            rec.recommendation = "decommission — no real traffic in window"
    elif rec.label == SHADOW:
        if unauth and rec.probe.data_classes:
            rec.recommendation = f"restrict immediately (require auth) and document — unauthenticated {classes}"
        elif unauth:
            rec.recommendation = "restrict (require auth) and document"
        else:
            rec.recommendation = "document the contract, then restrict to known consumers"
    else:
        rec.recommendation = "investigate — unaccounted-for route"


# --------------------------------------------------------------------------------------
# presentation
# --------------------------------------------------------------------------------------


def to_dicts(records: Iterable[EndpointRecord], now: datetime | None = None) -> list[dict[str, Any]]:
    return [r.to_dict(now) for r in records]


def render_table(records: Iterable[EndpointRecord]) -> str:
    rows = list(records)
    if not rows:
        return "(inventory empty)"
    order = {ACTIVE: 0, SHADOW: 1, ZOMBIE: 2, UNKNOWN: 3}
    rows.sort(key=lambda r: (order.get(r.label, 9), r.template))
    header = f"{'LABEL':8s} {'METHOD':6s} {'ENDPOINT':46s} {'AUTH?':6s} {'DAYS':5s} {'DATA':16s} OWNER"
    lines = [header, "-" * len(header)]
    for r in rows:
        auth = {True: "yes", False: "NO", None: "-"}[r.probe.auth_required]
        days = f"{r.age_days():.0f}" if r.last_seen else "-"
        data = ",".join(r.probe.data_classes) or "-"
        lines.append(
            f"{r.label.upper():8s} {r.method:6s} {r.template[:46]:46s} {auth:6s} {days:5s} "
            f"{data[:16]:16s} {r.owner}"
        )
    counts = {}
    for r in rows:
        counts[r.label] = counts.get(r.label, 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    lines.append("")
    lines.append(f"{len(rows)} endpoints: {summary}")
    lines.append("'-' = not probed (active endpoints are not probed; auth observed in captures instead)")
    return "\n".join(lines)


def version_pairs(records: Iterable[EndpointRecord]) -> list[tuple[EndpointRecord, str]]:
    """Pair versioned zombies with their current-version sibling, if one exists."""
    rows = list(records)
    templates = {r.template for r in rows}
    out: list[tuple[EndpointRecord, str]] = []
    for r in rows:
        if r.label != ZOMBIE:
            continue
        _, ids = template_of(r.template)
        tail = r.template
        for marker in ("/v1/", "/v2/", "/old/", "/legacy/"):
            if marker in tail:
                sibling = tail.replace(marker, "/")
                if sibling in templates:
                    out.append((r, sibling))
                break
        del ids
    return out
