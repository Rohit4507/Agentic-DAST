# Agentic Real-Time DAST

**Security agents that hunt vulnerabilities as the platform changes.**
Submission for TBO Security Hackathon 2026 — *Agentic Real-Time DAST*.

Every change to a B2B travel platform can open a hole, and the expensive ones are not
injection bugs — they are business-logic flaws: one agency reading another's booking, a
fare lowered in the request body, a refund paid twice. Periodic scanners miss them, and
the long list of false positives they emit costs more attention than it saves.

This repository implements the participant pack's agent loop as a **change-driven,
scope-disciplined pipeline in which the model explores and deterministic code proves**.

```bash
python -m target.app --port 8080            # 1. start the deliberately vulnerable target
python run.py all --approve-writes          # 2. inventory -> plan -> attacks -> verify -> report
python run.py guard-demo                    # 3. prove the safety layer refuses what it should
```

Standard library only. No API keys, no `pip install`, Python 3.10+.

---

## What it does

| Stage | Implementation | Output |
|---|---|---|
| **Detect change** | bundle hashing + route delta (`run.py diff`), gateway-log deltas | added/removed routes since the last run |
| **Learn the app** | HAR journeys per role + static JS harvest + 30-day gateway log + capped, scope-checked liveness probes | `work/inventory.json` |
| **Zombie / shadow** | three-way diff: traffic × bundle × declared spec | `active / zombie / shadow` per endpoint, with last traffic, auth reachability, data exposed, owner, recommendation |
| **Plan** | rule engine over the inventory, emitting a ranked test list with a rationale per test | `work/audit.jsonl` `plan` stage |
| **Execute safely** | every request through one fail-closed guard; writes behind a human-approval gate | `work/audit.jsonl` |
| **Verify** | dual-token replay, negative controls, ledger invariants, redacted minimum evidence | `work/findings/<id>/capsule.json` |
| **Triage** | dedupe fingerprint, business-context severity, owner mapping | `work/findings.json` |
| **Report** | ticket-shaped markdown + SARIF 2.1.0 + JSON | `work/REPORT.md`, `work/report.sarif` |
| **Retest** | replay the proof capsule, or re-execute the logic attack | `python run.py retest` |
| **Bonus** | OpenAPI 3.1 generated as a by-product of discovery | `work/openapi.generated.json` |

### One run, in full

```
LABEL    METHOD ENDPOINT                                AUTH?  DAYS  DATA             OWNER
ACTIVE   GET    /api/booking/{id}                       -      0     -                Bookings API team
...
SHADOW   GET    /api/internal/agency/AGENCY-A/export    NO     12    PII,financial    Supplier Integrations team
ZOMBIE   GET    /api/old/agency/{id}/summary            NO     -     financial        Platform Retirement backlog
ZOMBIE   GET    /api/test/debug                         NO     -     internal-config  Platform Engineering
ZOMBIE   GET    /api/v1/booking/{id}                    NO     -     PII,financial    Bookings API team (legacy)

13 endpoints: 9 active, 1 shadow, 3 zombie

F-003  [CRITICAL] 10.0  Unauthenticated shadow endpoint exposes PII, financial
                        GET /api/internal/agency/AGENCY-A/export
F-005  [CRITICAL] 10.0  Unauthenticated zombie endpoint exposes PII, financial
                        GET /api/v1/booking/{id}
F-007  [HIGH    ]  8.7  Skipped payment — booking 8184 confirmed with 0.00 paid
F-001  [HIGH    ]  8.3  Cross-tenant read: agency_b can read AGENCY-A bookingId 8842
F-006  [HIGH    ]  8.1  Double refund — booking 8413 was refunded twice
F-008  [HIGH    ]  7.9  Fare tampering — 8748 rebooked at 100.00 against a 5000.00 quote
F-004  [HIGH    ]  7.0  Unauthenticated zombie endpoint exposes financial
                        GET /api/old/agency/{id}/summary

dedupe: 8 raw hits -> 7 findings
guard: 39 checked, 0 refused, 39 sent
audit: 47 entries, chain intact
```

---

## The five decisions that carry the design

### 1. The scope allowlist is outside the model's reach

`dast/scope.py` is a chokepoint, not a checker. `ScopeConfig` is a frozen dataclass with
no setter; `ScopeGuard.check()` raises before a socket is opened; `dast/http.py` is the
only module that sends anything, and it always asks first.

It denies, by default, all of these:

```
off-allowlist host            -> host-not-allowed
/api/admin/users              -> path-denied            (deny beats allow)
/api/booking/../../admin      -> non-canonical-path     (traversal)
/api/booking/%2e%2e/admin     -> non-canonical-path     (encoding must not change meaning)
http://<allowed>@evil.example -> userinfo-in-url
DELETE /api/booking/8842      -> method-not-allowed
file:///etc/passwd            -> scheme-not-allowed
```

Plus a per-host token bucket, a hard request budget, a kill-switch file, strain-based
backoff when *our own* traffic starts drawing 5xx, and an append-only **hash-chained**
audit log. `verify_chain()` detects an edited line, a deleted line and a reordered log;
because a chain alone cannot detect *tail truncation*, each run publishes its head
(seq + hash) in `REPORT.md` and `findings.json`, and verification takes that head as an
argument. Redaction happens at the writer, not just the caller, so no secret can reach
the file even if some future component forgets. Redirects are never followed — a
redirect is a new URL and must re-pass the guard.

This matters twice over, because an agent that reads attacker-influenced content (JS
bundles, error messages, responses) is itself a prompt-injection target. Scope is in a
file a human wrote; nothing the agent ingests can widen it.

### 2. Precision is won in verification, not discovery

`test_cross_tenant_read` will not report unless all of this holds:

1. the owner's own request returns `200` (a baseline exists);
2. the **negative control** passes — a non-existent id returns `404`, proving the
   endpoint discriminates at all;
3. the other tenant's request returns `200`;
4. the two responses contain the **same object** (`bookingId` matches) — not a generic
   success page;
5. the returned `agencyId` **differs from the caller's own agency** — a real boundary;
6. sensitive fields are actually present.

Step 2 is the habit that saves the precision score, and step 5 is what stops "it
returned 200" from being mistaken for "it returned someone else's data". Seven tests in
`tests/test_verify.py` assert that the verifier stays **silent** when any one of these
fails — a `403`, a different object, a generic `{"status":"ok"}`, a broken control, a
missing baseline, a same-agency read.

### 3. Business logic is verified by arithmetic, not judgment

`dast/verify/invariants.py` states the flow's rules as code:

```
Σ refunds ≤ Σ payments        count(refunds) ≤ 1        CONFIRMED ⇒ paid > 0
final ≥ quoted                pax ≥ 1                   refunds ⇒ terminal state
```

An attack drives a real flow on a **synthetic booking created for the purpose**, then
reads the ledger back. The invariant *is* the proof: the ledger balances or it does not.
That is why logic findings can be reported with the same confidence as a `404` control —
and it is where conventional scanners have nothing to offer.

### 4. Severity is additive, because multiplicative saturates

CVSS is the floor; business context lifts it, and every finding prints its arithmetic:

```
CVSS floor 7.5 + 1.2 (cross_agency) + 1.5 (auth_bypass) + 0.6 (pii) = 10.8 -> capped at 10.0
```

The obvious model is `cvss × multiplier`, but the factors are correlated: 2.5 × 1.8 × 1.4
means nothing, and in practice it pins *every* business finding at 10.0 within one
release — which destroys the ranking the report exists to provide. Additive modifiers
keep the ordering sane (8.3 BOLA < 8.7 skipped payment < 10.0 unauthenticated PII) and
stay arguable line by line. `tests/test_endtoend.py::test_severity_is_not_saturated`
enforces this as a property, not a preference.

### 5. The LLM belongs in exactly one place

The shipped pipeline makes **zero model calls**. Discovery, execution and verification
are deterministic code, because that is the part that must not wobble.

The seat reserved for a model is `dast/pipeline.py:plan_tests()` — *given this inventory,
what should be tested next and why*. It returns `PlannedTest` objects constrained to the
`test_id` enum in `dast/attacks/registry.py` (16 catalogued tests, 5 implemented). A model
plugged in there can rank, explain and prioritise; it cannot invent a test, cannot send a
request, and cannot touch scope. That is the whole architecture in one sentence: **the
model explores, code validates.**

---

## What is in the box

```
run.py                      one command: all | inventory | guard-demo | retest | diff | catalogue
scope.json                  the allowlist — written by a human, read-only to everything else
assets.json                 asset ownership (provided input), longest-prefix match
dast/
  scope.py                  fail-closed allowlist, token bucket, budget, kill switch, strain backoff
  audit.py                  append-only JSONL with a hash chain + redaction
  http.py                   the only egress; no redirects, capped bodies, audited
  auth.py                   role -> token from env, fingerprints only in logs
  gate.py                   human-approval gate for write tests (fails closed)
  model.py                  EndpointRecord / Finding / TrafficHit + path templating
  pipeline.py               inventory -> plan -> execute -> verify -> report -> retest
  cli.py                    the commands above
  record/                   HAR reading/writing, journey recorder (stdlib + optional Playwright)
  inventory/                JS harvest, gateway-log correlation, three-way classification, OpenAPI
  attacks/                  BOLA, business-logic, unauthenticated exposure + the test library
  verify/                   proof capsules, negative controls, redaction, invariants
  report/                   ticket markdown, SARIF, severity, dedupe
target/                     deliberately vulnerable mock travel API (see target/README.md)
tests/                     112 stdlib unittest tests, including the precision cases
captures/                   recorded journeys, the "provided HAR" input
```

## Commands

```bash
python run.py all --approve-writes     # full loop
python run.py inventory                # discovery + zombie/shadow only
python run.py catalogue                # the test library (the planner's enum)
python run.py guard-demo               # 8 out-of-scope attempts, all refused; exit code 1 if any passes
python run.py retest                   # replay capsules / re-execute logic, auto-close fixed
python run.py diff --bundle target/static/app.js   # route delta since the last run
python -m unittest discover -s tests -t .          # 112 tests
```

Without `--approve-writes`, write tests are **skipped and reported as such** — the gate
fails closed in non-interactive runs rather than assuming consent.

Exit codes, so a CI job can tell the difference between "finished" and "was stopped":

| Code | Meaning |
|---|---|
| 0 | ran to completion |
| 1 | `guard-demo` only: an out-of-scope request was **allowed** (a failing safety check) |
| 2 | configuration or credential error, **including an unreachable target** |
| 3 | write tests skipped: approval required and not granted |
| 4 | stopped by kill switch or exhausted request budget |

A target that never answers is fatal, not clean: if every request in a stage failed,
the run exits 2 and says the target is unreachable rather than printing "no findings",
because an empty report from a dead host reads exactly like a secure one. See
`tests/test_endtoend.py::TestUnreachableTarget`.

`STOPPED` conditions propagate out of every per-request handler by design. A dropped
kill file or a spent budget ends the engagement; it must never degrade into a quiet
"probe skipped" note next to an exit code of 0 (that was a real bug, now covered by
`tests/test_scope.py::TestStoppingConditions`).

## Running it against a real target

1. Replace `base_url`, `allow_hosts`, `allow_paths`, `deny_paths` and `accounts` in
   `scope.json`. Credentials stay as `env:VAR` references; they are resolved at request
   time and never logged.
2. Record journeys: `dast/record/journey.py:record_with_playwright()` drives the UI per
   role and writes a HAR (needs `pip install playwright`). Or drop in the provided HARs.
3. Point `--gateway` at the 30–90 day gateway log (JSONL or combined log format).
4. Set `js_bundles` to the front-end bundles, and `assets_file` to the ownership table.
5. `python run.py all`.

If a signal is missing, the pipeline says so rather than guessing — no gateway log means
"last traffic: never", not "active".

## How this maps to the judging criteria

| Criterion | Weight | Where it is earned |
|---|---|---|
| Valid findings & severity | 30% | 5 vuln classes proven end to end; business-context severity with printed arithmetic |
| Precision & noise control | 20% | negative control on every test, 6-condition BOLA proof, 7 silence tests, dedupe ratio reported |
| Safety & scope discipline | 20% | frozen allowlist, 8 documented refusals, budget, kill switch, strain backoff, approval gate, hash-chained audit |
| Speed after change | 10% | `run.py diff` — bundle hash → route delta → test only what moved |
| Report quality & actionability | 10% | one ticket per finding: repro, redacted evidence, impact, owner, fix, retest command; SARIF for CI |
| Discovery & API inventory | 10% | zero-documentation API map, zombie/shadow labels with all six required fields, generated OpenAPI |

**Deliberately not built** (and why): a multi-agent swarm (coordination cost, no
verifiable output), a vector DB (the knowledge is a graph of endpoints, not fuzzy text),
a custom crawler (Playwright and katana exist), a dashboard (markdown scores, and it
takes ten minutes). Depth beats breadth on this rubric.

---

## Disclaimer

The `target/` application is intentionally insecure and must never be deployed. Scan only
systems you are authorised to test. The harness is built to make unauthorised action
difficult rather than merely discouraged — but the responsibility remains with the
operator.
