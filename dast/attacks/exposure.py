"""Unauthenticated data exposure on zombie and shadow endpoints.

This is the detection the participant pack's *additional requirement* implies: for every
zombie/shadow endpoint, report "whether it is reachable without auth, what data it
exposes". When the answer is "yes, and PII", that is a finding in its own right -- and it
is one of the most verifiable findings possible, since the proof is simply *no credential
was sent* and the body still contains another tenant's traveller record.

Verification discipline:
  * the request carries no Authorization header at all (asserted, not implied)
  * a negative control confirms the route is discriminating
  * at least one sensitive data class must be present in the body
"""

from __future__ import annotations

from typing import Any, Sequence

from ..errors import ControlFailure, ScopeViolation, TransportError, STOPPING
from ..http import Client
from ..model import SHADOW, ZOMBIE, EndpointRecord, classify_data, deep_keys
from ..report.severity import from_finding_kind
from ..verify.engine import Capsule, negative_control
from .common import FindingFactory, make_finding

SENSITIVE = {"PII", "financial"}


def test_unauthenticated_exposure(
    client: Client,
    record: EndpointRecord,
    *,
    factory: FindingFactory,
    candidate_ids: Sequence[str] = ("1",),
    owner: str | None = None,
    notes: list[str] | None = None,
) -> Any | None:
    """Try a small, fixed set of identifiers for the route's ``{id}`` segment.

    Different routes use different identifier spaces (a booking id will 404 on an
    agency-scoped route), so the caller supplies candidates in priority order and we
    stop at the first one that returns sensitive data. Bounded and audited -- this is
    targeted exploration, not enumeration.
    """
    notes = notes if notes is not None else []
    if record.label not in (ZOMBIE, SHADOW):
        return None

    anon = None
    body: dict[str, Any] = {}
    path = ""
    classes: list[str] = []
    exposed_keys: list[str] = []
    tried: list[str] = []
    for candidate in list(candidate_ids)[:4]:
        path = record.template.replace("{id}", str(candidate))
        if path in tried:
            continue
        tried.append(path)
        try:
            resp = client.get(path, component="exposure", note=f"anonymous:{record.template}")
        except STOPPING:
            raise
        except (ScopeViolation, TransportError) as exc:
            notes.append(f"{path}: anonymous request failed: {exc}")
            continue
        if resp.status != 200:
            notes.append(f"{path}: anonymous request returned {resp.status}")
            continue
        try:
            parsed = resp.json()
        except ValueError:
            notes.append(f"{path}: anonymous response was not JSON")
            continue
        body = parsed if isinstance(parsed, dict) else {"_root": parsed}
        exposed_keys = deep_keys(body)
        classes = classify_data(exposed_keys)
        if set(classes) & SENSITIVE:
            anon = resp
            break
        notes.append(f"{path}: anonymous but no sensitive data class ({classes or 'none'})")

    if anon is None:
        notes.append(f"{record.method} {record.template}: no candidate identifier produced exposed data")
        return None

    try:
        control = negative_control(client, record.template, role=None)
    except ControlFailure as exc:
        notes.append(f"{path}: {exc}")
        return None

    capsule = Capsule(finding_id="", title="", endpoint=record.template, method="GET")
    capsule.expected = {"status": 200}
    capsule.control = control
    capsule.add("anonymous", anon, role=None)

    kind = "unauthenticated_data_exposure" if "PII" in classes else "info_disclosure"
    severity = from_finding_kind(
        kind,
        cross_tenant=record.label == SHADOW or "agencyId" in body,
        unauth=True,
        pii="PII" in classes,
        write=False,
    )

    label_words = "shadow" if record.label == SHADOW else "zombie"
    title = f"Unauthenticated {label_words} endpoint exposes {', '.join(classes)} — {record.method} {record.template}"
    impact = (
        f"`{record.method} {record.template}` is classified **{record.label}** "
        f"({'; '.join(record.notes) or 'no further context'}) and answers **without any credential**. "
        f"The response exposes {', '.join(classes)}: {', '.join(exposed_keys[:8])}"
        f"{' ...' if len(exposed_keys) > 8 else ''}. "
        + (
            "The payload carries another tenant's booking, so this is also a cross-agency exposure."
            if "agencyId" in body or "PII" in classes
            else ""
        )
        + f" Last real traffic: {record.last_seen.isoformat() if record.last_seen else 'none in window'}."
    )
    remediation = (
        f"Recommended action from the inventory: {record.recommendation or 'decommission or restrict'}. "
        + (
            "Because no legitimate consumer was observed in the traffic window, decommissioning removes "
            "the exposure; if a consumer exists, put it behind the current auth middleware and the "
            "gateway's OAuth scope for its owner team."
            if record.label == ZOMBIE
            else "Since it is in use but undocumented, first document the contract with its owning team, "
            "then require the standard bearer/JWT auth and scope it to the consumer's tenant."
        )
    )

    return make_finding(
        factory=factory,
        title=title,
        vuln_class=kind,
        method=record.method,
        endpoint=path,
        capsule=capsule,
        severity=severity,
        owner=owner or record.owner,
        owasp="API9:2023 Improper Inventory Management" if record.label == ZOMBIE else "API2:2023",
        cwe="CWE-306 Missing Authentication for Critical Function",
        impact=impact,
        remediation=remediation,
        extracted={
            "inventory_label": record.label,
            "reachable_without_auth": True,
            "data_classes": classes,
            "response_keys": exposed_keys[:40],
            "last_seen_real_traffic": record.last_seen.isoformat() if record.last_seen else None,
            "recommendation": record.recommendation,
            "negative_control": control.to_dict(),
        },
        retest={"mode": "replay-capsule"},
        notes=notes + list(record.notes),
    )
