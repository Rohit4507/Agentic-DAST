"""Command line interface.

One command runs the loop::

    python run.py all --approve-writes

and every stage is separately demoable, because a live demo that requires three
terminals and manual steps is a live demo that fails.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__
from .attacks import registry
from .audit import verify_chain
from .deploy import DeployEvent, DeployState, assess
from .errors import ApprovalDenied, BudgetExhausted, DastError, KillSwitchEngaged, ScopeViolation
from .http import TransportOptions
from .inventory.classify import render_table
from .inventory.harvest import (
    changed_bundles,
    diff_route_sets,
    harvest_files,
    load_bundle_state,
    routes_from_state,
    save_bundle_state,
    union_routes,
)
from .model import ACTIVE, SHADOW, ZOMBIE, iso, utcnow
from .pipeline import (
    collect_inventory,
    open_engagement,
    plan_tests,
    retest_findings,
    run_all,
    write_inventory,
)

DEFAULT_SCOPE = "scope.json"
DEFAULT_OUT = "work"
DEFAULT_CAPTURES = "captures"
DEFAULT_GATEWAY = "target/traffic/gateway_30d.jsonl"


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _rule(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def _gateway_paths(value: str) -> list[Path]:
    p = Path(value)
    if p.is_dir():
        return sorted(list(p.glob("*.jsonl")) + list(p.glob("*.log")) + list(p.glob("*.txt")))
    return [p] if p.exists() else []


def _transport_args(parser: argparse.ArgumentParser) -> None:
    """Transport policy.  Every retry is charged to the budget and audited, so these
    knobs change how patient a run is, never how much it is allowed to do."""
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="retries on 429/503, each charged and audited (default 2; 0 disables)",
    )
    parser.add_argument(
        "--retry-max-wait",
        type=float,
        default=10.0,
        help="cap on a single Retry-After wait, seconds (default 10)",
    )
    parser.add_argument(
        "--max-wall-clock",
        type=float,
        default=0.0,
        help="stop the run after N seconds, exit 4 (default 0 = no limit)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="per-request timeout, seconds (default 15)",
    )


def _deploy_args(p: argparse.ArgumentParser) -> None:
    """A deploy event makes the loop incremental: test what changed, skip what did not."""
    p.add_argument(
        "--deploy-event",
        default="",
        help="CI event JSON; its changed routes are tested first",
    )
    p.add_argument(
        "--deploy-state",
        default="",
        help="where the last processed deploy is remembered (default: <out>/deploy_state.json)",
    )
    p.add_argument(
        "--changed-only",
        action="store_true",
        help="test only the routes the deploy touched, and say how many were deferred",
    )


def _transport(args: argparse.Namespace) -> TransportOptions:
    return TransportOptions(
        timeout=float(getattr(args, "timeout", 15.0) or 15.0),
        retries=int(getattr(args, "retries", 2) or 0),
        retry_max_wait=float(getattr(args, "retry_max_wait", 10.0) or 0.0),
        max_wall_clock=float(getattr(args, "max_wall_clock", 0.0) or 0.0),
    )


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scope", default=DEFAULT_SCOPE, help="scope allowlist JSON (default: scope.json)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output directory (default: work/)")
    parser.add_argument("--captures", default=DEFAULT_CAPTURES, help="directory of .har journey captures")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY, help="gateway/access log for the traffic window")
    parser.add_argument("--approve-writes", action="store_true", help="pre-approve write tests on synthetic objects")
    parser.add_argument("--no-probe", action="store_true", help="do not send inventory liveness probes")
    parser.add_argument("--no-writes", action="store_true", help="skip all write/logic tests")
    parser.add_argument("--max-probes", type=int, default=15, help="cap on inventory probes")
    parser.add_argument("--json", action="store_true", help="machine-readable summary on stdout")
    _transport_args(parser)


# --------------------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------------------


def _deploy_priority(args: argparse.Namespace, out: str | Path) -> tuple[list[str], str]:
    """Routes the last processed deploy touched, and the flag that asked us to only run them."""
    if getattr(args, "deploy_event", ""):
        event = DeployEvent.load(args.deploy_event)
        return event.routes(), f"event {event.sha[:8]}"
    state_path = Path(getattr(args, "deploy_state", "") or Path(out) / "deploy_state.json")
    if not state_path.exists():
        return [], ""
    state = DeployState.load(state_path)
    if not state.routes:
        return [], ""
    return list(state.routes), f"deploy {state.sha[:8]}"


def cmd_all(args: argparse.Namespace) -> int:
    eng = open_engagement(args.scope, args.out, approve_writes=args.approve_writes, transport=_transport(args))
    print(eng.cfg.summarize())
    gateway = _gateway_paths(args.gateway)
    priority, priority_source = _deploy_priority(args, args.out)
    if priority:
        verb = "only these" if args.changed_only else "first"
        print(f"deploy priority ({priority_source}): {len(priority)} route(s), testing {verb}")
        for route in priority:
            print(f"  * {route}")

    result = run_all(
        eng,
        capture_dir=args.captures,
        gateway_paths=gateway,
        approve_writes=args.approve_writes,
        include_writes=not args.no_writes,
        probe=not args.no_probe,
        max_probes=args.max_probes,
        priority=priority,
        only_priority=bool(args.changed_only and priority),
        on_inventory=lambda inv: _rule("INVENTORY (discovery + zombie/shadow)") or print(render_table(inv.records)),
    )

    _rule("PLAN (what the agent chose to test, and why)")
    if not result.plan:
        print("(nothing planned)")
    for p in result.plan:
        write = "write" if p.requires_write else "read "
        print(f"[{write}] {p.test_id:26s} {p.endpoint}")
        print(f"          {p.rationale}")

    _rule("FINDINGS (verified)")
    if not result.report.findings:
        print("no finding survived verification")
    for f in result.report.findings:
        print(f"{f.id}  [{f.severity.upper():13s}] {f.cvss:4.1f}  {f.title}")
        print(f"       owner: {f.owner}  |  {f.method} {f.endpoint}")
        print(f"       {f.business_impact}")
    print()
    print(f"dedupe: {result.report.dedupe.ratio}")
    print(f"approvals: {result.execution.approvals}")
    print(f"guard: {json.dumps(eng.guard.health_snapshot())}")
    ok, seq, detail = verify_chain(eng.audit.path)
    print(f"audit: {eng.audit.count()} entries, chain {'intact' if ok else f'BROKEN at {seq} ({detail})'}")
    print(f"elapsed: {result.elapsed_seconds:.2f}s")
    _rule("ARTEFACTS")
    for p in sorted(eng.out.rglob("*")):
        if p.is_file():
            print(f"  {p}")

    if args.json:
        print()
        print(json.dumps(result.to_dict(), indent=2, default=str))
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    eng = open_engagement(args.scope, args.out, transport=_transport(args))
    gateways = _gateway_paths(args.gateway)
    inv = collect_inventory(
        eng,
        capture_dir=args.captures,
        gateway_paths=gateways,
        probe=not args.no_probe,
        max_probes=args.max_probes,
    )
    write_inventory(eng, inv)
    print(render_table(inv.records))
    print()
    print(f"inventory  -> {eng.out / 'inventory.json'}")
    print(f"openapi    -> {eng.out / 'openapi.generated.json'}")
    print(f"probes sent: {inv.probes_sent}")

    from .pipeline import derive_role_agencies, plan_tests

    planned, _ = plan_tests(eng, inv, agency_by_role=derive_role_agencies(eng, eng.tokens.roles()),
                            include_writes=not args.no_writes)
    print()
    print(f"planned tests: {len(planned)}")
    for p in planned:
        print(f"  - {p.test_id:26s} {p.endpoint}")
    if args.json:
        print(json.dumps(inv.rows(), indent=2, default=str))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    return cmd_all(args)


def cmd_retest(args: argparse.Namespace) -> int:
    eng = open_engagement(args.scope, args.out, transport=_transport(args))
    root = Path(args.out) / "findings"
    if not root.exists():
        print(f"no findings directory at {root}; run 'python run.py all' first", file=sys.stderr)
        return 2
    results = retest_findings(eng, root)
    if getattr(args, "finding", None):
        wanted = {args.finding.upper()}
        results = [r for r in results if str(r.get("id", "")).upper() in wanted]
        if not results:
            print(f"no stored finding matching {args.finding}", file=sys.stderr)
            return 2
    if not results:
        print("nothing to retest")
        return 0
    for r in results:
        print(f"{r['status']:5s}  {r['id']}  ({r['mode']})  {r['detail']}")
    closed = [r for r in results if r["status"] == "fixed"]
    print()
    print(f"{len(results)} retested, {len(closed)} now fixed, "
          f"{sum(1 for r in results if r['status'] == 'open')} still open")
    if args.json:
        print(json.dumps(results, indent=2))
    return 0


def cmd_catalogue(args: argparse.Namespace) -> int:
    print(f"dast-agent {__version__} — test library ({len(registry.TESTS)} tests)\n")
    print(f"{'TEST_ID':28s} {'CLASS':32s} {'WRITE':6s} {'STATE':10s} OWASP")
    print("-" * 100)
    for t in registry.TESTS.values():
        print(
            f"{t.test_id:28s} {t.vuln_class:32s} {('yes' if t.requires_write else 'no'):6s} "
            f"{('implemented' if t.implemented else 'planned'):10s} {t.owasp}"
        )
    if args.json:
        print(json.dumps(registry.catalogue(), indent=2))
    return 0


def cmd_guard_demo(args: argparse.Namespace) -> int:
    """Prove the safety layer refuses things. Deliberately tries to break scope."""
    eng = open_engagement(args.scope, args.out, transport=_transport(args))
    base = eng.cfg.base_url
    attempts = [
        ("off-allowlist host", "GET", "https://example.com/api/bookings"),
        ("path never allowlisted", "GET", f"{base}/api/admin/users"),
        ("deny beats allow", "POST", f"{base}/api/refund/bulk"),
        ("path traversal", "GET", f"{base}/api/booking/../../admin/users"),
        ("percent-encoded traversal", "GET", f"{base}/api/booking/%2e%2e/admin"),
        ("userinfo smuggling", "GET", "http://127.0.0.1:8080@evil.example/api/bookings"),
        ("disallowed method", "DELETE", f"{base}/api/booking/8842"),
        ("non-http scheme", "GET", "file:///etc/passwd"),
    ]
    print(f"engagement: {eng.cfg.name}")
    print(eng.cfg.summarize())
    _rule("ATTEMPTS (all of these must be refused)")
    refused = 0
    for label, method, url in attempts:
        try:
            eng.guard.check(method, url, charge=False)
            print(f"  ALLOWED (!!)  {label:28s} {method} {url}")
        except ScopeViolation as exc:
            refused += 1
            print(f"  refused       {label:28s} {method} {url}")
            print(f"                -> {exc.reason}: {exc.detail}")
            eng.audit.denied(component="guard-demo", method=method, url=url,
                             reason=exc.reason, detail=exc.detail)

    _rule("ALLOWED (in scope, so it must pass)")
    allowed = 0
    for path in ("/healthz", "/api/booking/8842"):
        try:
            eng.guard.check("GET", f"{base}{path}", charge=False)
            allowed += 1
            print(f"  allowed       GET {path}")
        except ScopeViolation as exc:
            print(f"  refused (!!)  GET {path} -> {exc.reason}")

    _rule("BUDGET + KILL SWITCH")
    snapshot = eng.guard.health_snapshot()
    print(f"  budget: {eng.cfg.max_total_requests} requests, remaining {snapshot['budget_remaining']}")
    kill = Path(eng.cfg.kill_switch_file)
    print(f"  kill switch: create '{kill}' and the next request is refused before it is sent")
    ok, seq, detail = verify_chain(eng.audit.path)
    print(f"  audit: {eng.audit.count()} entries, chain {'intact' if ok else f'BROKEN at {seq}'} "
          f"-> {eng.audit.path}")
    print()
    print(f"{refused}/{len(attempts)} out-of-scope attempts refused, {allowed}/2 in-scope requests allowed")
    return 0 if refused == len(attempts) and allowed == 2 else 1


def _fetch_bundles(eng: Any, urls: list[str]) -> tuple[dict[str, str], set[str]]:
    """Fetch bundle URLs through the gated client: audited, budgeted, scope-checked."""
    hashes: dict[str, str] = {}
    routes: set[str] = set()
    for url in urls:
        resp = eng.client.get(url, component="change", note="bundle-fetch")
        if resp.status != 200:
            print(f"  bundle {url} -> {resp.status}; ignored", file=sys.stderr)
            continue
        from .inventory.harvest import harvest_text

        prefixes = eng.profile.bundle.route_prefixes
        found = harvest_text(resp.text, prefixes)
        import hashlib

        hashes[url] = hashlib.sha256(resp.body).hexdigest()
        routes |= found
        print(f"  bundle {url}: {len(found)} route(s), sha256:{hashes[url][:12]}")
        if not found:
            # Silence here would look identical to "nothing changed", which is worse
            # than a warning: say which prefixes were searched.
            print(
                f"  warning: no route starting with {', '.join(prefixes) or '<none>'} in {url}; "
                "check bundle.route_prefixes in the profile",
                file=sys.stderr,
            )
    return hashes, routes


def _diff_deploy_event(eng: Any, args: argparse.Namespace) -> int:
    event = DeployEvent.load(args.deploy_event)
    state_path = Path(args.out) / "deploy_state.json"
    previous = DeployState.load(state_path)

    if previous.already_processed(event):
        print(f"deploy {event.sha[:8]} already processed at {previous.processed_at or 'an earlier run'}")
        print(f"  {len(previous.routes)} route(s) were prioritised then; nothing to do")
        if args.json:
            print(json.dumps({"status": "already-processed", "state": previous.to_dict()}, indent=2))
        return 0

    print(f"deploy {event.sha[:8]}  {event.service or '<no service>'}  {event.at or '<no timestamp>'}")
    if event.actor:
        print(f"  actor: {event.actor}")
    if event.changed_paths:
        print(f"  changed paths ({len(event.changed_paths)}):")
        for path in event.changed_paths:
            print(f"    - {path}")

    bundle_hashes: dict[str, str] = {}
    bundle_routes: set[str] = set()
    urls = list(event.bundle_urls) + list(getattr(args, "bundle_url", []) or [])
    if urls:
        print("  fetching bundles through the guard:")
        bundle_hashes, bundle_routes = _fetch_bundles(eng, urls)

    assessment = assess(
        event,
        inventory_path=Path(args.out) / "inventory.json",
        previous=previous,
        bundle_routes=bundle_routes,
    )

    print()
    print(assessment.summary())
    if assessment.new_routes:
        print(f"  new since deploy {previous.sha[:8] or '<baseline>'}: {len(assessment.new_routes)} route(s)")
        for route in assessment.new_routes:
            print(f"    * {route}")
    if assessment.to_test:
        print("  test these first:")
        for route in assessment.to_test:
            print(f"    + {route}")
    if assessment.not_inventoried:
        print("  not yet inventoried (run 'python run.py inventory' to map them):")
        for route in assessment.not_inventoried:
            print(f"    ? {route}")
    if assessment.removed:
        print("  gone from the bundle (candidate for decommissioning if it still answers):")
        for route in assessment.removed:
            print(f"    - {route}")

    new_state = previous.record(
        event, assessment.to_test, now=utcnow(), bundle_routes=assessment.bundle_routes
    ).save(state_path)
    print()
    print(f"state -> {new_state}")
    eng.audit.note(
        stage="change",
        kind="deploy-event",
        sha=event.sha,
        service=event.service,
        routes=assessment.to_test,
        not_inventoried=assessment.not_inventoried,
        bundle_hashes=bundle_hashes,
    )
    if args.json:
        print(json.dumps(assessment.to_dict(), indent=2))
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Detect change: a CI deploy event (preferred) or a bundle hash diff."""
    eng = open_engagement(args.scope, args.out, transport=_transport(args))
    if getattr(args, "deploy_event", ""):
        return _diff_deploy_event(eng, args)
    state_file = eng.out / "bundle_state.json"
    state = load_bundle_state(state_file)
    bundles = list(args.bundle) if args.bundle else list(eng.cfg.js_bundles)
    results = harvest_files([b for b in bundles if Path(b).exists()], eng.profile.bundle.route_prefixes)
    if not results:
        print("no bundles found; pass --bundle path/to/app.js", file=sys.stderr)
        return 2

    changed = changed_bundles(results, state)
    new_routes = union_routes(results)
    old_routes = routes_from_state(state, [r.source for r in results])
    first_run = not state
    delta = diff_route_sets(old_routes, new_routes)
    if first_run:
        delta = {"added": sorted(new_routes), "removed": [], "unchanged": []}

    print(f"bundles: {len(results)}  changed since last run: {len(changed)}")
    for r in results:
        mark = "CHANGED" if any(c.source == r.source for c in changed) else "same   "
        print(f"  [{mark}] {r.source}  sha256:{r.sha256[:12]}  {len(r.routes)} routes")
    print()
    if first_run:
        print("first run: recording the baseline, so every route is 'new'")
    print(f"routes added   : {len(delta['added'])}")
    for r in delta["added"]:
        print(f"  + {r}   <- test this first")
    print(f"routes removed : {len(delta['removed'])}")
    for r in delta["removed"]:
        print(f"  - {r}   <- candidate for decommissioning if it still responds")
    print(f"routes unchanged: {len(delta['unchanged'])}  (not retested -- this is what makes the loop fast)")
    save_bundle_state(state_file, results)
    print()
    print(f"state -> {state_file}")
    if args.json:
        print(json.dumps(delta, indent=2))
    return 0


# --------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="run.py",
        description="Agentic real-time DAST: scope-checked inventory, targeted attacks, deterministic verification.",
    )
    ap.add_argument("--version", action="version", version=f"dast-agent {__version__}")
    sub = ap.add_subparsers(dest="command")

    p_all = sub.add_parser("all", help="run the full loop (inventory -> plan -> execute -> report)")
    _common(p_all)
    _deploy_args(p_all)
    p_all.set_defaults(func=cmd_all)

    p_inv = sub.add_parser("inventory", help="discovery + active/zombie/shadow labelling only")
    _common(p_inv)
    p_inv.set_defaults(func=cmd_inventory)

    p_scan = sub.add_parser("scan", help="alias for 'all'")
    _common(p_scan)
    _deploy_args(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_re = sub.add_parser("retest", help="re-run stored findings and auto-close fixed ones")
    p_re.add_argument("--scope", default=DEFAULT_SCOPE)
    p_re.add_argument("--out", default=DEFAULT_OUT)
    p_re.add_argument("--finding", default="", help="retest a single finding id (e.g. F-001)")
    p_re.add_argument("--json", action="store_true")
    _transport_args(p_re)
    p_re.set_defaults(func=cmd_retest, captures="", gateway="", approve_writes=False,
                      no_probe=True, no_writes=False, max_probes=0)

    p_cat = sub.add_parser("catalogue", help="list the test library (the planner's enum)")
    p_cat.add_argument("--json", action="store_true")
    p_cat.set_defaults(func=cmd_catalogue)

    p_gd = sub.add_parser("guard-demo", help="prove the scope guard refuses what it should")
    p_gd.add_argument("--scope", default=DEFAULT_SCOPE)
    p_gd.add_argument("--out", default=DEFAULT_OUT)
    p_gd.add_argument("--json", action="store_true")
    p_gd.set_defaults(func=cmd_guard_demo)

    p_diff = sub.add_parser("diff", help="bundle change detection: route delta since the last run")
    p_diff.add_argument("--scope", default=DEFAULT_SCOPE)
    p_diff.add_argument("--out", default=DEFAULT_OUT)
    p_diff.add_argument("--bundle", action="append", default=[])
    p_diff.add_argument(
        "--deploy-event",
        default="",
        help="JSON from CI: {sha, service, at, changed_paths[], bundle_urls[]}",
    )
    p_diff.add_argument(
        "--bundle-url",
        action="append",
        default=[],
        help="fetch a bundle over the scope-checked client (repeatable)",
    )
    p_diff.add_argument("--json", action="store_true")
    _transport_args(p_diff)
    p_diff.set_defaults(func=cmd_diff)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "command", None):
        ap.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except KillSwitchEngaged as exc:
        print(f"STOPPED — kill switch engaged ({exc.reason}); no further requests will be sent.", file=sys.stderr)
        return 4
    except BudgetExhausted as exc:
        print(f"STOPPED — request budget exhausted ({exc.detail}); no further requests will be sent.", file=sys.stderr)
        return 4
    except DastError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ApprovalDenied as exc:
        print(f"approval required: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
