"""Ticket-shaped reports.

The pack's "report quality and actionability" criterion is 10%, and the fastest way to
lose it is a wall of scanner output. One finding = one file = one ticket, with the
fields a fixer actually needs: endpoint, severity *with its arithmetic*, owner, exact
reproduction, minimal evidence, why it matters for the business, how to fix it, and how
it will be retested.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from ..model import Finding, iso


def _fmt_evidence(ev: dict[str, Any] | None) -> str:
    if not ev:
        return "_no evidence captured_"
    req = ev.get("request") or {}
    resp = ev.get("response") or {}
    lines = [
        "```http",
        f"{req.get('method', 'GET')} {req.get('path', '')}",
        f"Authorization: {req.get('credential', '<none>')}",
        "```",
        "",
        f"Response: `{resp.get('status', '?')}`"
        + (f"  ·  {ev.get('redactions', 0)} value(s) masked (PII policy)" if ev.get("redactions") else ""),
        "",
        "```json",
        (resp.get("excerpt") or "").strip() or "{}",
        "```",
    ]
    extracted = ev.get("extracted") or {}
    if extracted.get("negative_control"):
        nc = extracted["negative_control"]
        lines += [
            "",
            f"**Negative control passed:** `{nc.get('path')}` → `{nc.get('status')}` "
            f"(expected {nc.get('expected')}). The endpoint discriminates between real and "
            f"non-existent objects, so the 200 above is meaningful.",
        ]
    if extracted.get("reproduce"):
        lines += ["", "**Reproduce:**", "", "```bash", str(extracted["reproduce"]), "```"]
    return "\n".join(lines)


def render_ticket(finding: Finding, *, engagement: str = "", extra: dict[str, Any] | None = None) -> str:
    ev = finding.evidence.to_dict() if finding.evidence else None
    extracted = (ev or {}).get("extracted") or {}
    parts: list[str] = [
        f"# [{finding.severity.upper()}] {finding.title}",
        "",
        "| | |",
        "|---|---|",
        f"| **Finding** | `{finding.id}` |",
        f"| **Endpoint** | `{finding.method} {finding.endpoint}` |",
        f"| **Severity** | **{finding.severity}** ({finding.cvss:.1f}) — {finding.business_impact} |",
        f"| **Owner** | {finding.owner} |",
        f"| **Class** | {finding.vuln_class} · {finding.owasp} · {finding.cwe} |",
        f"| **Confidence** | {finding.confidence} |",
        f"| **Engagement** | {engagement or 'n/a'} |",
        f"| **Detected** | {iso(finding.created_at)} |",
        "",
        "## Impact",
        "",
        finding.impact or "_not recorded_",
        "",
        "## Evidence (minimum, redacted)",
        "",
        _fmt_evidence(ev),
        "",
        "## Fix",
        "",
        finding.remediation or "_not recorded_",
        "",
        "## Retest",
        "",
    ]
    mode = (finding.retest or {}).get("mode", "replay-capsule")
    if mode == "re-execute":
        parts += [
            f"This is a business-logic finding, so the retest **re-executes the attack** "
            f"(`{finding.retest.get('test_id')}`, role `{finding.retest.get('role')}`) rather than "
            f"replaying a static request — the state has to be rebuilt for the invariant to be checked.",
            "",
            "```bash",
            f"python run.py retest --finding {finding.id}",
            "```",
        ]
    else:
        parts += [
            "The proof capsule below is replayed verbatim after a fix. If the flawed response shape is "
            "gone, the finding closes automatically.",
            "",
            "```bash",
            f"python run.py retest --finding {finding.id}",
            "```",
        ]
    if finding.retest.get("reproduce"):
        parts += ["", "```bash", str(finding.retest["reproduce"]), "```"]

    if extracted.get("violated_invariants"):
        parts += ["", "## Invariants violated", "", "| Invariant | Why it is a bug |", "|---|---|"]
        for inv in extracted["violated_invariants"]:
            parts.append(f"| `{inv.get('invariant')}` | {inv.get('detail')} |")
        ledger = extracted.get("ledger") or {}
        if ledger:
            parts += [
                "",
                "```",
                f"booking {ledger.get('bookingId')}: status={ledger.get('status')} "
                f"quoted={ledger.get('quotedAmount')} final={ledger.get('finalAmount')} "
                f"paid={ledger.get('paid')} refunded={ledger.get('refunded')} "
                f"refunds={ledger.get('refundCount')}",
                "```",
            ]

    if finding.notes:
        parts += ["", "## Analyst notes", ""]
        parts += [f"- {n}" for n in finding.notes if n]

    if extra:
        parts += ["", "## Metadata", "", "```json", json.dumps(extra, indent=2), "```"]
    return "\n".join(parts) + "\n"


def finding_json(finding: Finding) -> dict[str, Any]:
    return finding.to_dict()


def write_findings(
    findings: Iterable[Finding],
    outdir: str | Path,
    *,
    engagement: str = "",
) -> list[Path]:
    base = Path(outdir)
    base.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for f in findings:
        d = base / f.id
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.md").write_text(render_ticket(f, engagement=engagement), encoding="utf-8")
        (d / "finding.json").write_text(json.dumps(finding_json(f), indent=2, default=str), encoding="utf-8")
        capsule = getattr(f, "capsule", None)
        if capsule is not None:
            (d / "capsule.json").write_text(
                json.dumps(capsule.to_dict(), indent=2, default=str), encoding="utf-8"
            )
        written.append(d / "report.md")
    return written


def render_index(
    findings: list[Finding],
    *,
    engagement: str,
    scope_summary: str,
    inventory_rows: list[dict[str, Any]] | None = None,
    dedupe_ratio: str = "",
    approvals: str = "",
    guard_stats: dict[str, Any] | None = None,
    audit_summary: dict[str, Any] | None = None,
    started: str = "",
    elapsed_seconds: float = 0.0,
) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    head = [
        "# Vulnerability scan report",
        "",
        f"**Engagement:** {engagement}  ",
        f"**Scope:** {scope_summary}  ",
        f"**Run:** {started} ({elapsed_seconds:.1f}s)  ",
        f"**Findings:** {len(findings)} — "
        + ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: kv[0]))
        if findings
        else "**Findings:** none",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        head += ["No finding survived verification. See the noise-control section for what was tested and discarded.", ""]
    else:
        head += ["| ID | Severity | Class | Endpoint | Owner |", "|---|---|---|---|---|"]
        for f in findings:
            head.append(
                f"| [{f.id}]({f.id}/report.md) | **{f.severity}** ({f.cvss:.1f}) | {f.vuln_class} | "
                f"`{f.method} {f.endpoint}` | {f.owner} |"
            )
        head.append("")

    head += ["## Noise control", ""]
    if dedupe_ratio:
        head.append(f"- Dedupe: {dedupe_ratio} (fingerprint = class + normalised endpoint).")
    head.append(f"- Human approvals: {approvals or 'none requested'}.")
    if guard_stats:
        head.append(
            f"- Scope guard: {guard_stats.get('checked', 0)} requests checked, "
            f"{guard_stats.get('denied', 0)} refused before sending, "
            f"{guard_stats.get('sent', 0)} sent, budget remaining {guard_stats.get('budget_remaining', 0)}, "
            f"strain pauses {guard_stats.get('strain_pauses', 0)}."
        )
    if audit_summary:
        head.append(
            f"- Audit log: {audit_summary.get('entries', 0)} entries, hash chain "
            + ("intact" if audit_summary.get("chain_ok") else f"BROKEN — {audit_summary.get('chain_detail')}")
            + (
                f"; head seq {audit_summary.get('head_seq')} "
                f"sha256:{str(audit_summary.get('head_hash'))[:12]} (recorded here and in findings.json)."
                if audit_summary.get("head_seq")
                else "."
            )
        )
    head.append("")

    if inventory_rows:
        non_active = [r for r in inventory_rows if r.get("label") != "active"]
        head += [
            "## API inventory (discovery)",
            "",
            f"{len(inventory_rows)} endpoints discovered; "
            f"{len(inventory_rows) - len(non_active)} active, "
            f"{sum(1 for r in non_active if r.get('label') == 'zombie')} zombie, "
            f"{sum(1 for r in non_active if r.get('label') == 'shadow')} shadow.",
            "",
        ]
        if non_active:
            head += [
                "| Label | Endpoint | Last traffic | No auth? | Data exposed | Owner | Recommendation |",
                "|---|---|---|---|---|---|---|",
            ]
            for r in non_active:
                auth = "yes" if r.get("reachable_without_auth") else ("no" if r.get("reachable_without_auth") is False else "?")
                head.append(
                    f"| {r.get('label')} | `{r.get('method')} {r.get('path_template')}` | "
                    f"{(r.get('last_seen_real_traffic') or 'never')[:10]} | {auth} | "
                    f"{', '.join(r.get('data_exposed') or []) or '-'} | {r.get('owner')} | "
                    f"{r.get('recommendation')} |"
                )
            head.append("")
    return "\n".join(head) + "\n"
