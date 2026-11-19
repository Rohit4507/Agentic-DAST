# Implementation plan — finalised

**Agentic Real-Time DAST · TBO Security Hackathon 2026 (VOYAGEHACK 4.0)**
Owner: Rohit Singh Rajput · Repository: `github.com/Rohit4507/Agentic-DAST`
Status: **prototype complete and verified** (2026-11-19) → **4 weeks to the live platform** (26 Nov – 24 Dec)

---

## 1. What the judges actually reward

From the participant pack (`Fraud Prevention & Security.pdf`, p.5):

| Criterion | Weight | The pack asks for | Where we answer it |
|---|---|---|---|
| Valid findings & severity | 30% | real, reproducible flaws; business context, not a generic score | 7 verified findings across 3 classes; additive business modifiers, printed arithmetic |
| Precision & noise control | 20% | few false positives and duplicates | negative control on every test; 8 raw hits → 7 findings; silence tests |
| Safety & scope discipline | 20% | in scope, self-limited load, human decides | one fail-closed chokepoint; 8/8 refusals; budget, kill switch, approval gate, hash chain |
| Speed after change | 10% | short deploy → verified finding | bundle-hash + route delta, `run.py diff` |
| Report quality & actionability | 10% | drop into a ticket, retested on fix | per-finding ticket, SARIF, owner, retest capsule |
| Discovery & API inventory | 10% | map without a spec; zombie/shadow + recommendation; OpenAPI bonus | 13 endpoints (9/1/3), owners, generated OpenAPI |

Two of the pack's statements drive the whole plan: *"Breaking these rules disqualifies a submission, however many findings it has"* and *"Teams may go deep on a few stages if they show how the rest would plug in."* So: never trade safety for count, and spend the four weeks deepening rather than widening.

---

## 2. Baseline — measured today, not claimed

Reproduce with `python3 -m unittest discover -s tests -t .` and `python3 run.py all --approve-writes` against `python3 -m target.app --port 8080`.

| Metric | Value | Source |
|---|---|---|
| Findings | **7** (2 critical, 5 high) | `work/findings.json` |
| Raw hits → findings | **8 → 7** (1 duplicate removed) | `dedupe:` line |
| Endpoints | **13** = 9 active / 1 shadow / 3 zombie | `work/inventory.json` |
| Requests audited | **39** checked, 0 denied, p95 **1.3 ms**, budget 81/120 left | `guard:` line |
| Guard refusals | **8/8** out-of-scope attempts refused, 2/2 in-scope allowed | `run.py guard-demo` |
| Audit | **47** entries, chain intact, head published | `work/audit.head.json` |
| Tests | **112**, ~2.1 s | `unittest discover` |
| Catalogue | **16** tests, **5** implemented | `run.py catalogue` |
| Dependencies / model calls | **0 / 0** | stdlib imports only |
| End-to-end | **3.89 s** | `run.py all` |

Findings: F-003 CRIT 10.0 (unauth shadow export) · F-005 CRIT 10.0 (unauth zombie `/api/v1/booking/{id}`) · F-007 HIGH 8.7 (skipped payment) · F-001 HIGH 8.3 (cross-tenant read) · F-006 HIGH 8.1 (double refund) · F-008 HIGH 7.9 (fare tampering) · F-004 HIGH 7.0 (unauth zombie agency summary).

---

## 3. Gap analysis — honest

### 3.1 The eight stages of the pack's loop

| Stage | State | Note |
|---|---|---|
| Detect change | **partial** | bundle hash + route delta implemented; **no deploy webhook** — it is invoked by hand |
| Learn the app / inventory | **built** | HAR journeys per role, JS harvest, 30-day gateway log, capped probes, three-way classification |
| Plan attacks | **built** | rule engine over the inventory, ranked with a rationale per test |
| Execute safely | **built** | single chokepoint, bucket, budget, kill switch, approval gate |
| Verify | **built** | dual-token replay, negative controls, ledger invariants, redacted capsules |
| Triage | **built** | dedupe fingerprint, additive severity, owner from asset register |
| Report | **built** | ticket markdown + SARIF 2.1.0 + JSON, head of audit published |
| Retest | **built** | capsule replay + logic re-execution, auto-close |

**Only one stage is short: detect change is manual.** Everything else exists.

### 3.2 The eight vulnerability classes in scope

| Class | State | Evidence / gap |
|---|---|---|
| Access control | **deep** | BOLA F-001, 6-condition proof + negative control |
| Business logic | **deep** | F-006 double refund, F-007 skipped payment, F-008 fare tampering |
| Zombie & shadow APIs | **deep** | 3 zombie + 1 shadow with last traffic, auth reachability, data exposed, owner, recommendation; OpenAPI bonus done |
| Data exposure | **good** | PII/financial dumps proven and redacted in evidence |
| API hygiene | **partial** | unauthenticated endpoints proven; mass assignment, excessive data, missing rate limit are catalogue entries only |
| Authentication & sessions | **gap** | `auth_token_reuse`, `auth_jwt_weakness` are `planned` |
| Injection | **gap** | `injection_sql` is `planned` |
| Server-side risks | **gap** | `ssrf_supplier_url` is `planned` |

**5 of 16 catalogue tests implemented, covering 3 of 8 classes deeply.** That is the one number the plan exists to change.

### 3.3 Inputs the pack promises that we simulate

Today the pipeline reads `captures/*.har`, `target/traffic/gateway_30d.jsonl`, `target/static/app.js` and a local mock. The pack gives a live staging portal, real gateway logs, CI/CD deploy events and DNS/certificate data. Replacing fixtures with adapters is week 1 — the pipeline's seams already accept these as paths in `scope.json`.

---

## 4. The four weeks

Each week has one theme, a hard exit test, and the rubric weight it moves. A week that misses its exit test does not start the next one — that rule is what keeps the demo honest.

### Week 1 · 26 Nov – 3 Dec — real inputs, and the trigger that makes it "real-time"

*Serves: speed after change (10%) · discovery (10%)*

1. `dast/record/journey.py` — record HARs against staging with the provided test accounts, one journey per role (agency A agent, agency B agent, sub-agent).
2. Deploy trigger — a webhook receiver that runs `run.py all --since-deploy`: bundle hash diff → route delta → **only the moved endpoints are tested**.
3. Adapters — combined-log gateway parser (nginx/ALB), DNS/certificate watcher stub feeding the inventory as a fourth source, config profiles so target switch is `scope.json` only.
4. Keep the mock target as an offline fallback so a failed demo network cannot take the run down.

**Exit test:** edit one route in `app.js`; `run.py all --since-deploy` sends **≤ 5 requests**, finishes **< 5 s**, and names the changed endpoint. A no-op deploy sends **0** attack requests.

### Week 2 · 4–10 Dec — close the catalogue gap, 5 → 11 implemented

*Serves: valid findings & severity (30%) · precision (20%)*

1. Implement `auth_token_reuse`, `auth_jwt_weakness` (authentication & sessions).
2. Implement `injection_sql`, `ssrf_supplier_url` (injection, server-side).
3. Implement `hygiene_mass_assignment`, `exposure_excessive_data` (API hygiene, data exposure).
4. Every new test ships a **silence test**: the verifier must stay quiet when the control fails (403, different object, generic `{"status":"ok"}`, broken control, missing baseline).
5. Plant the matching bugs in `target/` — documented in `target/README.md` — so each class produces at least one **verified** finding, not a catalogue row.

**Exit test:** `run.py catalogue` reports **11 implemented**; suite grows 112 → **≥ 150**; a full run reports findings across **≥ 5 classes**; every new finding has a capsule that replays.

### Week 3 · 11–17 Dec — publish the speed number, and make CI the operator

*Serves: speed after change (10%) · report quality (10%)*

1. GitHub Action: `run.py all` on every push, **SARIF upload**, fail the job on a new critical.
2. Time-to-finding: record deploy timestamp → verified finding, write `deploy_to_finding_ms` into `findings.json` and the run header in `REPORT.md`.
3. `run.py diff` median and p95, printed and published in the report.
4. Keep `work/audit.head.json` as a CI artefact so the chain can be verified after the fact.

**Exit test:** ten consecutive commits, `p50 deploy → verified finding` published and **< 10 min**; CI goes red on an intentionally introduced critical; audit chain verifies from the published head.

### Week 4 · 18–24 Dec — harden, route, and record the demo

*Serves: safety (20%) · actionability (10%)*

1. Owner routing: `assets.json` prefix → team; optional Jira/webhook ticket creation from `work/findings/F-*/report.md`.
2. Operator runbook: start, stop, kill switch drill, budget exhaustion, approval policy, what to do when the target dies.
3. Two live drills: kill switch aborts mid-run (exit 4, zero further requests); budget exhaustion aborts identically. Both recorded.
4. 90-second demo video: deploy → delta → attack → proof → ticket, with the guard refusing an out-of-scope request on camera.
5. Final deck refresh with the week-3 numbers.

**Exit test:** a full run against staging with **0 out-of-scope requests, 0 guard violations**, findings across ≥ 5 classes, every finding owned and retested; demo recorded; runbook reviewed by someone who has never run the tool.

---

## 5. Risks, and what is already done about them

| Risk | Impact | Mitigation | State |
|---|---|---|---|
| A dead target reports "clean" | worst failure a scanner has | total transport failure is fatal, exit 2, `TestUnreachableTarget` | **done** |
| Over-eager verifier files noise | precision score | negative control + 6-condition BOLA proof + silence tests | **done**, extended in week 2 |
| Scope creep mid-run | disqualification | frozen allowlist, deny beats allow, longest prefix wins | **done** |
| Fixture drift hides a real change | false confidence | live HAR + live gateway log replace fixtures | week 1 |
| Demo network failure | zero score on stage | offline mock target, one command, no dependencies to install | **done** |
| Stopping conditions swallowed by a broad `except` | silent overrun | `StoppingCondition` re-raised first in every per-request handler, locked by tests | **done** |

---

## 6. Definition of done for the submission

- [x] 7 verified findings, each with a replayable capsule and an owner
- [x] 13 endpoints classified active / zombie / shadow with a recommendation each
- [x] guard-demo proves 8/8 refusals; budget and kill switch abort with exit 4
- [x] hash-chained audit with a published head; tamper tests (edit/delete/reorder/truncate)
- [x] 112 tests, standard library only, no install step
- [x] OpenAPI 3.1 generated as a by-product
- [ ] deploy webhook → delta run (week 1)
- [ ] 11 of 16 catalogue tests implemented, ≥ 5 classes proven (week 2)
- [ ] published p50 deploy → verified finding (week 3)
- [ ] staging run with 0 guard violations + 90 s demo (week 4)

---

## 7. Deliberately out of scope, with reasons

- **Multi-agent swarm** — coordination cost, no verifiable output. One guarded loop beats five chatty agents.
- **LLM in the security path** — non-determinism exactly where proof is required. The seam (`plan_tests()`) exists; the shipped path makes zero model calls, and that is a feature, not a gap.
- **Vector database** — the knowledge is a graph of endpoints, not fuzzy text.
- **Custom crawler / dashboard** — Playwright and katana exist; markdown and SARIF already score. Depth beats breadth on this rubric.

---

*Numbers in this document are the ones the code prints; if a week changes them, the document changes with it.*
