"""The loop: detect -> inventory -> plan -> execute -> verify -> report -> retest.

The stage boundaries are explicit because the pack's loop is explicit, and because the
*plan* is where an LLM belongs (stage 3) while everything else is deterministic. Today
:func:`plan_tests` is a rule engine; swapping in a model that returns
``{test_id, rationale}`` for the same enum would not change a line of the executor.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .attacks import registry
from .attacks.bola import BolaTarget, candidate_targets, test_cross_tenant_read
from .attacks.common import FindingFactory
from .attacks.exposure import test_unauthenticated_exposure
from .attacks.logic import LogicContext, test_double_refund, test_fare_tampering, test_skipped_payment
from .audit import AuditLog, audit_head, verify_chain
from .auth import TokenStore
from .errors import STOPPING, DastError, ScopeViolation, TransportError
from .fields import first
from .gate import ApprovalGate
from .http import Client
from .inventory.classify import build_inventory, probe_candidates, render_table, to_dicts
from .inventory.harvest import harvest_files, union_routes
from .inventory.openapi import build_spec, write_spec
from .inventory.traffic import load_asset_map, read_gateway_log
from .model import ACTIVE, SHADOW, ZOMBIE, EndpointRecord, Finding, TrafficHit, iso, utcnow
from .profile import StepSpec, TargetProfile
from .record.har import merge_hits, read_har
from .report.dedupe import DedupeReport, dedupe
from .report.sarif import write_sarif
from .report.ticket import render_index, write_findings
from .scope import ScopeConfig, ScopeGuard
from .verify.engine import Capsule, replay_capsule
from .verify.ledger_source import build_ledger_source

# --------------------------------------------------------------------------------------
# engagement
# --------------------------------------------------------------------------------------


@dataclass
class Engagement:
    cfg: ScopeConfig
    guard: ScopeGuard
    audit: AuditLog
    tokens: TokenStore
    client: Client
    out: Path
    profile: TargetProfile = field(default_factory=TargetProfile.mock_defaults)
    started: datetime = field(default_factory=utcnow)

    def path(self, *parts: str) -> Path:
        p = self.out.joinpath(*parts)
        if parts and not p.suffix:
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
        return p


# --------------------------------------------------------------------------------------
# profile loading
# --------------------------------------------------------------------------------------

_DOC_PATH = re.compile(r"\{[^}]+\}")


def _norm_route(path: str) -> str:
    """``/api/ledger/{id}`` and ``/api/ledger/:id`` both become ``/api/ledger``."""
    path = (path or "/").split("?", 1)[0].split("#", 1)[0]
    path = _DOC_PATH.sub("", path)
    path = re.sub(r"/:[A-Za-z_][A-Za-z0-9_]*", "", path)
    path = re.sub(r"/+", "/", path).rstrip("/")
    return path or "/"


def routes_outside_scope(cfg: ScopeConfig, profile: TargetProfile) -> list[str]:
    """Flow paths the allowlist does not cover.

    A profile that points at paths the guard will refuse is a configuration bug that
    presents as "the tests just did not find anything".  Fail at open time instead.
    """
    allowed = tuple(_norm_route(p) for p in cfg.allow_paths)
    denied = tuple(_norm_route(p) for p in cfg.deny_paths)
    bad: list[str] = []
    paths = [step.path for step in profile.flows.steps.values()]
    if profile.ledger.adapter == "http" and profile.ledger.endpoint:
        paths.append(profile.ledger.endpoint)
    for raw in paths:
        route = _norm_route(raw)
        covered = any(route == a or route.startswith(a + "/") for a in allowed)
        blocked = any(route == d or route.startswith(d + "/") for d in denied)
        if not covered or blocked:
            bad.append(raw)
    return bad


def load_profile(cfg: ScopeConfig, scope_file: Path) -> TargetProfile:
    """Explicit profile, resolved relative to the scope file; else the mock defaults."""
    if not cfg.profile:
        return TargetProfile.mock_defaults()
    candidate = Path(cfg.profile)
    if not candidate.is_absolute():
        candidate = (scope_file.resolve().parent / candidate).resolve()
    profile = TargetProfile.load(candidate)
    outside = routes_outside_scope(cfg, profile)
    if outside:
        raise DastError(
            "profile names paths the scope allowlist does not permit: "
            + ", ".join(sorted(set(outside)))
            + ". Add them to allow_paths or fix the profile -- otherwise every flow "
            "test stops at the guard and the run reports nothing."
        )
    return profile


def _route_present(template: str, present: Iterable[str]) -> bool:
    """Template equality that tolerates ``{id}`` vs ``:id`` and trailing slashes."""
    want = _norm_route(template)
    return any(_norm_route(p) == want for p in present)


def open_engagement(
    scope_path: str | Path,
    outdir: str | Path,
    *,
    approve_writes: bool = False,
    component: str = "pipeline",
    timeout: float = 15.0,
) -> Engagement:
    scope_file = Path(scope_path)
    cfg = ScopeConfig.load(scope_file)
    profile = load_profile(cfg, scope_file)
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(out / "audit.jsonl")
    guard = ScopeGuard(cfg)
    tokens = TokenStore(dict(cfg.accounts))
    client = Client(guard, audit, tokens, component=component, timeout=timeout)
    eng = Engagement(cfg=cfg, guard=guard, audit=audit, tokens=tokens, client=client, out=out, profile=profile)
    audit.note(
        stage="engagement-open",
        engagement=cfg.name,
        scope=cfg.summarize(),
        allow_hosts=list(cfg.allow_hosts),
        allow_paths=list(cfg.allow_paths),
        deny_paths=list(cfg.deny_paths),
        budget=cfg.max_total_requests,
        approve_writes=approve_writes,
        profile=profile.name,
        profile_source=profile.source,
        profile_summary=profile.summarize(),
    )
    return eng


# --------------------------------------------------------------------------------------
# stage 2: inventory
# --------------------------------------------------------------------------------------


@dataclass
class InventoryResult:
    records: list[EndpointRecord]
    har_hits: list[TrafficHit]
    js_routes: set[str]
    bundle_hashes: dict[str, str]
    probes_sent: int = 0

    @property
    def known_object_ids(self) -> list[str]:
        ids: list[str] = []
        for h in self.har_hits:
            for i in h.object_ids:
                if i not in ids:
                    ids.append(i)
        return ids

    def rows(self) -> list[dict[str, Any]]:
        return to_dicts(self.records)


def collect_inventory(
    eng: Engagement,
    *,
    capture_dir: str | Path | None = None,
    gateway_paths: Iterable[str | Path] = (),
    probe: bool = True,
    max_probes: int = 15,
    window_days: int | None = None,
) -> InventoryResult:
    cfg = eng.cfg
    capture_paths = sorted(Path(capture_dir).glob("*.har")) if capture_dir and Path(capture_dir).exists() else []
    har_hits: list[TrafficHit] = []
    for p in capture_paths:
        har_hits.extend(read_har(p, role=p.stem))

    gateway_hits: list[TrafficHit] = []
    for gp in gateway_paths:
        gateway_hits.extend(read_gateway_log(gp))

    js_results = harvest_files(
        [b for b in cfg.js_bundles if Path(b).exists()], eng.profile.bundle.route_prefixes
    )
    js_routes = union_routes(js_results)
    asset_map = load_asset_map(cfg.assets_file) if cfg.assets_file else {}

    records = build_inventory(
        har_hits=har_hits,
        gateway_hits=gateway_hits,
        js_routes=js_routes,
        declared_routes=(),
        window_days=window_days or cfg.traffic_window_days,
        asset_map=asset_map,
    )

    probes_sent = 0
    if probe:
        roles = eng.tokens.roles()
        # identifier candidates: tenant ids first (several routes are agency-scoped),
        # then object ids harvested from the caller's own traffic.
        probe_ids = list(dict.fromkeys(list(cfg.role_agencies.values()) + _har_object_ids(har_hits))) or ["1"]
        probes_sent = probe_candidates(
            eng.client,
            records,
            roles=roles[:1] or ("anonymous",),
            known_ids=probe_ids,
            max_probes=max_probes,
        )
        # Fail fast: if the very first batch all failed, the rest of the run would be
        # a page of fabricated quiet. Say the target is down instead.
        _require_live_target(eng, stage="inventory probe")

    eng.audit.note(
        stage="inventory",
        endpoints=len(records),
        active=sum(1 for r in records if r.label == ACTIVE),
        zombie=sum(1 for r in records if r.label == ZOMBIE),
        shadow=sum(1 for r in records if r.label == SHADOW),
        har_files=[str(p) for p in capture_paths],
        js_bundles=[r.source for r in js_results],
        probes_sent=probes_sent,
    )
    return InventoryResult(
        records=records,
        har_hits=har_hits,
        js_routes=js_routes,
        bundle_hashes={r.source: r.sha256 for r in js_results},
        probes_sent=probes_sent,
    )


def _require_live_target(eng: Engagement, *, stage: str) -> None:
    """Refuse to call a run "clean" when nothing ever answered.

    A target that is down produces zero findings, which is indistinguishable from a
    target that is secure. Reporting that as a pass is the worst failure mode a DAST
    tool has, so total transport failure is fatal instead.
    """
    stats = eng.guard.stats
    if stats.sent and stats.failed == stats.sent:
        raise DastError(
            f"target unreachable: all {stats.sent} request(s) failed during the {stage} stage, "
            f"so 'no findings' would be meaningless rather than good news. "
            f"Check that {eng.cfg.base_url} is serving "
            f"(for the bundled mock: python3 -m target.app --port 8080)."
        )


def _har_object_ids(hits: Iterable[TrafficHit]) -> list[str]:
    ids: list[str] = []
    for h in hits:
        for i in h.object_ids:
            if i not in ids:
                ids.append(i)
    return ids


def write_inventory(eng: Engagement, inv: InventoryResult) -> Path:
    path = eng.path("inventory.json")
    path.write_text(
        json.dumps(
            {
                "engagement": eng.cfg.name,
                "generated_at": iso(utcnow()),
                "traffic_window_days": eng.cfg.traffic_window_days,
                "endpoints": inv.rows(),
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    spec = build_spec(inv.records, base_url=eng.cfg.base_url or "", title=f"{eng.cfg.name} (inferred)")
    write_spec(eng.path("openapi.generated.json"), spec)
    return path


# --------------------------------------------------------------------------------------
# stage 3: plan
# --------------------------------------------------------------------------------------


@dataclass
class PlannedTest:
    test_id: str
    endpoint: str
    rationale: str
    requires_write: bool
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "endpoint": self.endpoint,
            "rationale": self.rationale,
            "requires_write": self.requires_write,
            "payload": self.payload,
        }


def derive_role_agencies(eng: Engagement, roles: Iterable[str]) -> dict[str, str]:
    """Which tenant does each test account belong to?

    Config first (``role_agencies`` in scope.json), then ask the target's own listing
    endpoint -- at whatever path and key the profile names, nested or not.  If neither
    works we return nothing for that role and simply do not run cross-tenant tests:
    guessing here would manufacture false positives.
    """
    out = dict(eng.cfg.role_agencies)
    spec = eng.profile.agency
    for role in roles:
        if role in out:
            continue
        for path in spec.probe_paths:
            try:
                resp = eng.client.get(path, role=role, component="planner", note="role-agency")
            except STOPPING:
                raise
            except (ScopeViolation, TransportError):
                continue
            if resp.status != 200:
                continue
            try:
                body = resp.json()
            except ValueError:
                continue
            if not isinstance(body, dict):
                continue
            value = first(body, spec.fields)
            if value is not None:
                out[role] = str(value)
                break
    if any(role not in out for role in roles):
        eng.audit.note(
            stage="planner",
            kind="agency-unresolved",
            roles_missing=[r for r in roles if r not in out],
            probe_paths=list(spec.probe_paths),
            fields=list(spec.fields),
            detail="cross-tenant tests are skipped for these roles",
        )
    return out


def plan_tests(
    eng: Engagement,
    inv: InventoryResult,
    *,
    agency_by_role: dict[str, str],
    include_writes: bool = True,
    bola_object_ids: int = 2,
    max_bola_targets: int = 4,
) -> tuple[list[PlannedTest], list[BolaTarget]]:
    """Deterministic, explainable test plan. This is the seam an LLM planner plugs into."""
    plan: list[PlannedTest] = []
    roles = eng.tokens.roles()
    profile = eng.profile
    exclude = tuple(profile.bola.exclude_templates)
    ident = profile.identifiers

    # --- cross-tenant object reads on active object-bearing endpoints --------------
    bola_targets: list[BolaTarget] = []
    for rec in inv.records:
        if rec.label != ACTIVE or rec.method != "GET" or "{id}" not in rec.template:
            continue
        if any(m in rec.template for m in exclude):
            continue  # the profile says these routes belong to the exposure test
        ids_by_role = _object_ids_for_template(inv.har_hits, rec.template)
        if not ids_by_role:
            continue
        for owner_role, ids in ids_by_role.items():
            targets = candidate_targets(
                template=rec.template,
                object_ids=ids,
                roles=[owner_role] + [r for r in roles if r != owner_role],
                agency_by_role=agency_by_role,
                owner=rec.owner,
                limit=profile.bola.max_targets_per_id or bola_object_ids,
                identity_field=ident.identity_field,
                boundary_field=ident.boundary_field,
                identity_candidates=ident.identity_candidates,
                boundary_candidates=ident.boundary_candidates,
                object_noun=ident.object_noun,
            )
            bola_targets.extend(targets)
            if targets:
                _add_planned(
                    plan,
                    PlannedTest(
                        test_id="bola_dual_token",
                        endpoint=rec.template,
                        rationale=(
                            f"active, takes an object id, and {owner_role} owns {len(ids)} object(s) we "
                            f"may read; replay the same GET as another tenant — content divergence "
                            f"proves broken object-level authorization"
                        ),
                        requires_write=False,
                        payload={"targets": len(targets)},
                    ),
                )
    seen_pairs: set[tuple[str, str, str]] = set()
    deduped: list[BolaTarget] = []
    for t in bola_targets:
        pair = (t.object_id, t.owner_role, t.other_role)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        deduped.append(t)
    bola_targets = deduped[:max_bola_targets]

    # --- unauthenticated exposure on zombie/shadow rows ----------------------------
    for rec in inv.records:
        if rec.label not in (ZOMBIE, SHADOW):
            continue
        if rec.probe.reachable is False:
            continue
        _add_planned(
            plan,
            PlannedTest(
                test_id="exposure_unauthenticated",
                endpoint=rec.template,
                rationale=(
                    f"{rec.label} endpoint: "
                    + ("no real traffic in the window but still in the bundle" if rec.label == ZOMBIE
                       else "in real traffic but absent from every bundle")
                    + "; probe said authentication is "
                    + {False: "not required", True: "required", None: "unknown"}[rec.probe.auth_required]
                    + f"; data classes: {', '.join(rec.probe.data_classes) or 'none observed'}"
                ),
                requires_write=False,
            ),
        )

    # --- business logic on the booking flow ---------------------------------------
    # The profile decides *which endpoint implements which step*, and a missing step
    # means the test is not planned at all -- with the reason recorded, so a target
    # without a rebook route does not look like a target that passed the test.
    present = {r.template for r in inv.records}
    skipped: list[dict[str, str]] = []
    if include_writes:
        flow = profile.flows
        for test_id, step_name, rationale in (
            (
                "logic_double_refund",
                "refund",
                "Refund endpoint is reachable and the ledger is readable: a second refund after the "
                "first must violate sigma(refunds) <= sigma(paid).",
            ),
            (
                "logic_skipped_payment",
                "confirm",
                "Confirm endpoint exists and the ledger exposes payment state: confirming without paying "
                "must violate CONFIRMED => paid > 0.",
            ),
            (
                "logic_fare_tampering",
                "rebook",
                "Rebook accepts an amount field on a live booking: a client-supplied value below the "
                "quote must violate final >= quoted.",
            ),
        ):
            step = flow.get(step_name)
            if step is None:
                skipped.append({"test_id": test_id, "reason": f"profile has no {step_name!r} step"})
                continue
            if not flow.has("hold"):
                skipped.append({"test_id": test_id, "reason": "flow tests need a 'hold' step to open a booking"})
                continue
            if not _route_present(step.path, present):
                skipped.append(
                    {
                        "test_id": test_id,
                        "reason": f"{step.path} is not an inventoried route",
                    }
                )
                continue
            if not profile.ledger.usable:
                skipped.append(
                    {
                        "test_id": test_id,
                        "reason": "no ledger adapter: the invariant cannot be proven, only asserted",
                    }
                )
                continue
            _add_planned(
                plan, PlannedTest(test_id=test_id, endpoint=step.path, rationale=rationale, requires_write=True)
            )
    if skipped:
        eng.audit.note(stage="planner", kind="tests-skipped", skipped=skipped)

    eng.audit.note(
        stage="plan",
        planned=len(plan),
        by_test={t.test_id: sum(1 for p in plan if p.test_id == t.test_id) for t in plan},
        bola_targets=len(bola_targets),
        profile=profile.name,
        skipped=[s["test_id"] for s in skipped],
    )
    return plan, bola_targets


def _add_planned(plan: list[PlannedTest], item: PlannedTest) -> None:
    """One row per (test_id, endpoint); merge the rationale and payload of duplicates."""
    for existing in plan:
        if existing.test_id == item.test_id and existing.endpoint == item.endpoint:
            if item.rationale not in existing.rationale:
                existing.rationale += "; " + item.rationale
            for k, v in item.payload.items():
                existing.payload[k] = existing.payload.get(k, 0) + v
            return
    plan.append(item)


def _object_ids_for_template(hits: Iterable[TrafficHit], template: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for h in hits:
        if h.template != template or not h.role or not h.object_ids:
            continue
        bucket = out.setdefault(h.role, [])
        for i in h.object_ids:
            if i not in bucket:
                bucket.append(i)
    return out


# --------------------------------------------------------------------------------------
# stages 4-5: execute + verify
# --------------------------------------------------------------------------------------


@dataclass
class ExecutionResult:
    findings: list[Finding]
    notes: list[str]
    approvals: str
    planned: int
    executed: int


def execute_plan(
    eng: Engagement,
    plan: list[PlannedTest],
    bola_targets: list[BolaTarget],
    inv: InventoryResult,
    *,
    gate: ApprovalGate,
    factory: FindingFactory | None = None,
) -> ExecutionResult:
    factory = factory or FindingFactory()
    findings: list[Finding] = []
    notes: list[str] = []
    executed = 0
    roles = eng.tokens.roles()
    logic_role = roles[0] if roles else "agency_a"

    def owner_for(endpoint: str) -> str:
        for rec in inv.records:
            if rec.template == endpoint or rec.template.replace("{id}", "") in endpoint:
                return rec.owner
        return "unassigned"

    # --- BOLA ----------------------------------------------------------------------
    if any(p.test_id == "bola_dual_token" for p in plan):
        for target in bola_targets:
            executed += 1
            f = test_cross_tenant_read(eng.client, target, factory=factory, notes=notes)
            if f:
                findings.append(f)

    # --- unauthenticated exposure --------------------------------------------------
    exposure_rows = [p for p in plan if p.test_id == "exposure_unauthenticated"]
    object_ids = inv.known_object_ids or ["1"]
    agency_ids = list(dict.fromkeys(eng.cfg.role_agencies.values())) or ["AGENCY-A"]
    for p in exposure_rows:
        rec = next((r for r in inv.records if r.template == p.endpoint and r.label in (ZOMBIE, SHADOW)), None)
        if rec is None:
            continue
        # a route scoped by agency needs a tenant id, not a booking id
        candidates = agency_ids + object_ids if "agency" in rec.template.lower() else object_ids
        executed += 1
        f = test_unauthenticated_exposure(
            eng.client, rec, factory=factory, candidate_ids=candidates, owner=rec.owner, notes=notes
        )
        if f:
            findings.append(f)

    # --- business logic ------------------------------------------------------------
    write_plan = [p for p in plan if p.requires_write]
    if write_plan:
        ctx = LogicContext(
            client=eng.client,
            gate=gate,
            factory=factory,
            role=logic_role,
            owner=owner_for(eng.profile.flows.path("refund")),
            flow=eng.profile.flows,
            ledger=build_ledger_source(eng.profile.ledger, eng.client),
            ids=eng.profile.identifiers,
        )
        runners = {
            "logic_double_refund": test_double_refund,
            "logic_skipped_payment": test_skipped_payment,
            "logic_fare_tampering": test_fare_tampering,
        }
        for p in write_plan:
            runner = runners.get(p.test_id)
            if runner is None:
                continue
            executed += 1
            ctx.notes = []
            f = runner(ctx)  # type: ignore[operator]
            if f:
                findings.append(f)
        notes.extend(ctx.notes)

    eng.audit.note(
        stage="execute",
        planned=len(plan),
        executed=executed,
        findings=len(findings),
        approvals=gate.summary,
    )
    return ExecutionResult(
        findings=findings, notes=notes, approvals=gate.summary, planned=len(plan), executed=executed
    )


# --------------------------------------------------------------------------------------
# stage 6: triage + report
# --------------------------------------------------------------------------------------


@dataclass
class ReportResult:
    findings: list[Finding]
    dedupe: DedupeReport
    index_path: Path
    sarif_path: Path
    json_path: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": len(self.findings),
            "dedupe": self.dedupe.ratio,
            "index": str(self.index_path),
            "sarif": str(self.sarif_path),
            "json": str(self.json_path),
        }


def write_reports(
    eng: Engagement,
    findings: Iterable[Finding],
    inv: InventoryResult,
    *,
    approvals: str = "",
    elapsed_seconds: float = 0.0,
) -> ReportResult:
    unique, dedupe_report = _safe_dedupe(findings)
    findings_dir = eng.out / "findings"
    write_findings(unique, findings_dir, engagement=eng.cfg.name)

    # The report stage's own audit entry must be written *before* the head is taken,
    # otherwise the published head is stale by one line and the log looks truncated.
    eng.audit.note(stage="report", findings=len(unique), dedupe=dedupe_report.ratio,
                   approvals=approvals)
    head_seq, head_hash = audit_head(eng.audit.path)
    chain_ok, bad_seq, chain_detail = verify_chain(eng.audit.path, expect_head=(head_seq, head_hash))

    index = render_index(
        unique,
        engagement=eng.cfg.name,
        scope_summary=eng.cfg.summarize(),
        inventory_rows=inv.rows(),
        dedupe_ratio=dedupe_report.ratio,
        approvals=approvals,
        guard_stats=eng.guard.health_snapshot(),
        audit_summary={
            "entries": head_seq,
            "chain_ok": chain_ok,
            "chain_detail": "verified" if chain_ok else f"{chain_detail} at seq {bad_seq}",
            "head_seq": head_seq,
            "head_hash": head_hash,
        },
        started=iso(eng.started),
        elapsed_seconds=elapsed_seconds,
    )
    index_path = eng.out / "REPORT.md"
    index_path.write_text(index, encoding="utf-8")

    sarif_path = write_sarif(eng.out / "report.sarif", unique)
    json_path = eng.out / "findings.json"
    json_path.write_text(
        json.dumps(
            {
                "engagement": eng.cfg.name,
                "generated_at": iso(utcnow()),
                "dedupe": dedupe_report.to_dict(),
                "approvals": approvals,
                "guard": eng.guard.health_snapshot(),
                "audit_chain_ok": chain_ok,
                "audit_head": {"seq": head_seq, "entry_hash": head_hash},
                "findings": [f.to_dict() for f in unique],
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    # A standalone anchor, so a reviewer can verify the log without parsing the report:
    #   verify_chain("work/audit.jsonl", expect_head=(head["seq"], head["entry_hash"]))
    (eng.out / "audit.head.json").write_text(
        json.dumps(
            {
                "log": str(eng.audit.path),
                "entries": head_seq,
                "seq": head_seq,
                "entry_hash": head_hash,
                "chain_ok": chain_ok,
                "verify": 'verify_chain("<log>", expect_head=(seq, entry_hash))',
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return ReportResult(unique, dedupe_report, index_path, sarif_path, json_path)


def _safe_dedupe(findings: Iterable[Finding]) -> tuple[list[Finding], DedupeReport]:
    from .report.dedupe import by_severity

    unique, report = dedupe(findings)
    return by_severity(unique), report


# --------------------------------------------------------------------------------------
# stage 8: retest
# --------------------------------------------------------------------------------------


def retest_findings(eng: Engagement, findings_root: str | Path) -> list[dict[str, Any]]:
    """Re-run every stored finding. ``open`` means still exploitable."""
    results: list[dict[str, Any]] = []
    root = Path(findings_root)
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        fjson = d / "finding.json"
        if not fjson.exists():
            continue
        finding = json.loads(fjson.read_text(encoding="utf-8"))
        mode = (finding.get("retest") or {}).get("mode", "replay-capsule")
        status, detail = _retest_one(eng, d, finding, mode)
        results.append({"id": finding.get("id"), "mode": mode, "status": status, "detail": detail})
        eng.audit.note(stage="retest", finding=finding.get("id"), mode=mode, status=status,
                       detail=detail[:200])
    return results


def _retest_one(eng: Engagement, d: Path, finding: dict[str, Any], mode: str) -> tuple[str, str]:
    if mode == "re-execute":
        spec = registry.TESTS.get(str((finding.get("retest") or {}).get("test_id")))
        if spec is None or spec.run is None:
            return "error", f"no runner for test {finding.get('retest', {}).get('test_id')}"
        gate = ApprovalGate(auto=True, audit=eng.audit)
        ctx = LogicContext(
            client=eng.client,
            gate=gate,
            factory=FindingFactory(),
            role=(finding.get("retest") or {}).get("role", "agency_a"),
            owner=finding.get("owner", "unassigned"),
            flow=eng.profile.flows,
            ledger=build_ledger_source(eng.profile.ledger, eng.client),
            ids=eng.profile.identifiers,
        )
        try:
            again = spec.run(ctx)
        except Exception as exc:  # noqa: BLE001
            return "error", f"re-execution failed: {exc}"
        return ("open", "invariant still violated") if again else ("fixed", "invariant now holds")

    capsule_path = d / "capsule.json"
    if not capsule_path.exists():
        return "error", "no capsule stored for this finding"
    raw = json.loads(capsule_path.read_text(encoding="utf-8"))
    capsule = _capsule_from_dict(raw)
    still, detail = replay_capsule(capsule, eng.client)
    return ("open" if still else "fixed"), detail


def _capsule_from_dict(raw: dict[str, Any]) -> Capsule:
    from .verify.engine import CapsuleStep, ControlResult

    steps = [
        CapsuleStep(
            label=s.get("label", ""),
            role=None if s.get("role") in (None, "<anonymous>") else s.get("role"),
            method=(s.get("request") or {}).get("method", "GET"),
            path=(s.get("request") or {}).get("path", ""),
            status=(s.get("response") or {}).get("status", 0),
            signature=(s.get("response") or {}).get("signature", {}),
            body_excerpt=(s.get("response") or {}).get("body_excerpt", ""),
            redactions=(s.get("response") or {}).get("redactions", 0),
        )
        for s in raw.get("steps", [])
    ]
    nc = raw.get("negative_control")
    control = (
        ControlResult(
            path=nc.get("path", ""),
            status=nc.get("status", 0),
            expected=tuple(nc.get("expected", [])),
            passed=bool(nc.get("passed")),
            detail=nc.get("detail", ""),
        )
        if nc
        else None
    )
    return Capsule(
        finding_id=raw.get("finding_id", ""),
        title=raw.get("title", ""),
        endpoint=raw.get("endpoint", ""),
        method=raw.get("method", "GET"),
        steps=steps,
        expected=raw.get("expected", {}),
        control=control,
        created_at=raw.get("created_at", ""),
    )


# --------------------------------------------------------------------------------------
# the whole loop in one call
# --------------------------------------------------------------------------------------


@dataclass
class RunResult:
    inventory: InventoryResult
    plan: list[PlannedTest]
    execution: ExecutionResult
    report: ReportResult
    elapsed_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "inventory": {
                "endpoints": len(self.inventory.records),
                "zombie": sum(1 for r in self.inventory.records if r.label == ZOMBIE),
                "shadow": sum(1 for r in self.inventory.records if r.label == SHADOW),
            },
            "plan": [p.to_dict() for p in self.plan],
            "execution": {
                "planned": self.execution.planned,
                "executed": self.execution.executed,
                "findings": len(self.execution.findings),
                "approvals": self.execution.approvals,
            },
            "report": self.report.to_dict(),
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "guard": None,
        }


def run_all(
    eng: Engagement,
    *,
    capture_dir: str | Path | None = None,
    gateway_paths: Iterable[str | Path] = (),
    approve_writes: bool = False,
    include_writes: bool = True,
    probe: bool = True,
    max_probes: int = 15,
    on_inventory: Any = None,
) -> RunResult:
    t0 = time.monotonic()
    inv = collect_inventory(
        eng, capture_dir=capture_dir, gateway_paths=gateway_paths, probe=probe, max_probes=max_probes
    )
    write_inventory(eng, inv)
    if on_inventory:
        on_inventory(inv)

    agency_by_role = derive_role_agencies(eng, eng.tokens.roles())
    planned, bola_targets = plan_tests(
        eng, inv, agency_by_role=agency_by_role, include_writes=include_writes
    )

    gate = ApprovalGate(auto=approve_writes, audit=eng.audit)
    execution = execute_plan(eng, planned, bola_targets, inv, gate=gate)
    elapsed = time.monotonic() - t0
    _require_live_target(eng, stage="probe")
    report = write_reports(eng, execution.findings, inv, approvals=execution.approvals, elapsed_seconds=elapsed)
    return RunResult(inv, planned, execution, report, elapsed)
