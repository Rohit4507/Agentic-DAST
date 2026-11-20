"""Broken object-level authorization (BOLA / IDOR) by dual-identity replay.

The cheapest high-precision test in API security: send *the same request* twice, once
as the object's owner and once as a different tenant, and prove the second response
carries the first object's data. No payloads, no enumeration, no guessing.

Guardrails baked in:
  * object ids come from the caller's own captured traffic (never enumerated)
  * a negative control runs first and voids the test if the endpoint answers anything
  * the finding requires an identity match *and* a tenant-boundary mismatch
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..errors import ControlFailure, ScopeViolation, TransportError, STOPPING
from ..http import Client, Response
from ..fields import first
from ..model import classify_data, deep_keys
from ..report.severity import from_finding_kind
from ..verify.engine import Capsule, compare_identity, negative_control, redact_body
from .common import FindingFactory, make_finding

PII_PROOF_KEYS = ("passport", "email", "phone", "traveller", "pax", "card", "dob")


@dataclass
class BolaTarget:
    template: str
    owner_role: str
    other_role: str
    owner_agency: str
    other_agency: str
    object_id: str
    identity_field: str = "bookingId"
    boundary_field: str = "agencyId"
    owner: str = "unassigned"
    #: Dotted-path ladders from the profile; empty means "the fields above, then synonyms".
    identity_candidates: tuple[str, ...] = ()
    boundary_candidates: tuple[str, ...] = ()
    object_noun: str = "booking"


def _safe_json(resp: Response) -> dict[str, Any] | None:
    try:
        body = resp.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def test_cross_tenant_read(
    client: Client,
    target: BolaTarget,
    *,
    factory: FindingFactory,
    notes: list[str] | None = None,
) -> Any | None:
    """Return a proven :class:`~dast.model.Finding`, or ``None``. Never guesses."""
    notes = notes if notes is not None else []
    path = target.template.replace("{id}", target.object_id)

    # 1. the owner's own view -- baseline
    try:
        owner_resp = client.get(
            path, role=target.owner_role, component="bola", note=f"owner-view:{target.template}"
        )
    except STOPPING:
        raise
    except (ScopeViolation, TransportError) as exc:
        notes.append(f"{path}: baseline request failed: {exc}")
        return None
    if owner_resp.status != 200:
        notes.append(f"{path}: owner role got {owner_resp.status}; not a usable baseline")
        return None

    # 2. negative control -- must be run before we believe any 200
    try:
        control = negative_control(client, target.template, role=target.owner_role)
    except ControlFailure as exc:
        notes.append(f"{path}: {exc}")
        return None

    # 3. the cross-tenant replay
    try:
        other_resp = client.get(
            path, role=target.other_role, component="bola", note=f"cross-tenant:{target.template}"
        )
    except (ScopeViolation, TransportError) as exc:
        notes.append(f"{path}: cross-tenant request failed: {exc}")
        return None

    if other_resp.status in (401, 403):
        notes.append(f"{path}: correctly refused for {target.other_role} ({other_resp.status})")
        return None
    if other_resp.status != 200:
        notes.append(f"{path}: unexpected status {other_resp.status} for {target.other_role}")
        return None

    # 4. same object? (not a generic page that merely returns 200)
    identity = compare_identity(
        owner_resp,
        other_resp,
        identity_field=target.identity_field,
        identity_candidates=target.identity_candidates,
    )
    if identity is None:
        notes.append(f"{path}: responses are not the same object; discarding")
        return None

    other_body = _safe_json(other_resp) or {}
    caller_agency = first(other_body, [*target.boundary_candidates, target.boundary_field])

    # 5. cross a real tenant boundary (this is what makes it a *security* finding)
    if caller_agency is None:
        notes.append(f"{path}: no {target.boundary_field} in the response; cannot prove a boundary crossing")
        return None
    if str(caller_agency) == str(target.other_agency):
        notes.append(f"{path}: {target.other_role} received its own object; not a finding")
        return None

    # 6. did real data come back?  Census every key at every depth: a wrapper object
    # whose only sensitive content is nested is the normal real-world case.
    all_keys = deep_keys(other_body)
    exposed_keys = [k for k in all_keys if k in PII_PROOF_KEYS]
    data_classes = classify_data(all_keys)

    capsule = Capsule(finding_id="", title="", endpoint=target.template, method="GET")
    capsule.expected = {
        "status": 200,
        "identity_field": target.identity_field,
        "identity_value": identity["identity_value"],
        "boundary_field": target.boundary_field,
        "expected_owner_agency": target.owner_agency,
    }
    capsule.control = control
    capsule.add("as_owner", owner_resp, role=target.owner_role)
    capsule.add("as_cross_tenant", other_resp, role=target.other_role)

    redacted_body, _ = redact_body(other_body)
    severity = from_finding_kind(
        "bola",
        cross_tenant=True,
        unauth=False,
        pii=bool(data_classes and "PII" in data_classes),
        write=False,
    )

    noun = target.object_noun
    endpoint_display = target.template.replace("{id}", f"{{{noun} id}}")
    title = (
        f"Cross-tenant read: {target.other_role} can read {target.owner_agency} "
        f"{noun} {identity['identity_value']}"
    )
    impact = (
        f"A token issued to {target.other_role} ({target.other_agency}) retrieves a {noun} owned by "
        f"{target.owner_agency} from `GET {target.template}`. The handler authenticates the caller but "
        f"never compares the object's {target.boundary_field} with the caller's tenant, so any "
        f"authenticated agency can read any other agency's {noun} by supplying its id — including "
        f"{', '.join(exposed_keys) if exposed_keys else noun + ' detail'}."
    )
    remediation = (
        f"Enforce object ownership in the authorization layer rather than the handler: reject the request "
        f"unless the object's `{target.boundary_field}` equals the caller's tenant, and scope the database "
        f"query by tenant so an unowned id is indistinguishable from a missing one. Add a regression test "
        f"that replays the two-token pair stored in this finding's proof capsule."
    )

    finding = make_finding(
        factory=factory,
        title=title,
        vuln_class="bola",
        method="GET",
        endpoint=path,
        capsule=capsule,
        severity=severity,
        owner=target.owner,
        owasp="API1:2023 Broken Object Level Authorization",
        cwe="CWE-639 Authorization Bypass Through User-Controlled Key",
        impact=impact,
        remediation=remediation,
        extracted={
            "object_id": identity["identity_value"],
            "identity_field": identity["identity_field"],
            "boundary_field": target.boundary_field,
            "owner_agency": target.owner_agency,
            "caller_role": target.other_role,
            "caller_agency": str(caller_agency),
            "objects_same": True,
            "fields_exposed": exposed_keys,
            "data_classes": data_classes,
            "redacted_response": redacted_body,
            "negative_control": control.to_dict(),
        },
        notes=notes,
    )
    return finding


def candidate_targets(
    *,
    template: str,
    object_ids: Iterable[str],
    roles: Iterable[str],
    agency_by_role: dict[str, str],
    owner: str,
    limit: int = 3,
    identity_field: str = "bookingId",
    boundary_field: str = "agencyId",
    identity_candidates: tuple[str, ...] = (),
    boundary_candidates: tuple[str, ...] = (),
    object_noun: str = "booking",
) -> list[BolaTarget]:
    """Build owner/other role pairs for one object-bearing endpoint.

    ``roles`` must contain at least two roles from *different* agencies; we only test
    the ordered pairs where the agencies actually differ.
    """
    role_list = list(roles)
    out: list[BolaTarget] = []
    for owner_role in role_list:
        for other_role in role_list:
            if owner_role == other_role:
                continue
            a_owner = agency_by_role.get(owner_role)
            a_other = agency_by_role.get(other_role)
            if not a_owner or not a_other or a_owner == a_other:
                continue
            for oid in list(object_ids)[:limit]:
                out.append(
                    BolaTarget(
                        template=template,
                        owner_role=owner_role,
                        other_role=other_role,
                        owner_agency=a_owner,
                        other_agency=a_other,
                        object_id=str(oid),
                        owner=owner,
                        identity_field=identity_field,
                        boundary_field=boundary_field,
                        identity_candidates=identity_candidates,
                        boundary_candidates=boundary_candidates,
                        object_noun=object_noun,
                    )
                )
    return out
