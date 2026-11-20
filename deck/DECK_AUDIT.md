# Deck audit — `Enxapse_Agentic_DAST_Idea_Submission.pdf`

Every figure and mechanism the deck states, checked against a run on this branch
(`main (PR #5)`). Anything marked **FIX** is checkable by a judge in under
a minute and should be corrected before submitting.

Reproduce the numbers: `bash deck/video/verify_numbers.sh` → all PASS, exit 0.

## Verified true (no change needed)

| Deck claim | Verified | Source |
|---|---|---|
| 7 proven findings, 2 critical / 5 high | 7 · 10.0, 10.0, 8.7, 8.3, 8.1, 7.9, 7.0 | `python3 run.py all --approve-writes` |
| 13 endpoints, 9 active / 1 shadow / 3 zombie | same | same run, inventory table |
| 39 requests, 0 denied, 81 of 120 left | same | guard line of the same run |
| 47 audit entries, hash-chained | `audit: 47 entries, chain intact` | same run |
| 16 catalogued tests | `test library (16 tests)` | `python3 run.py catalogue` |
| 8 hits → 7 findings (dedupe) | `8 raw hits -> 7 findings` | same run |
| 8 / 8 out-of-scope refused | `8/8 out-of-scope attempts refused, 2/2 in-scope requests allowed` | `python3 run.py guard-demo` |
| 120-request budget, 8 rps/host, kill switch, approval gate | match `scope.json` | `scope.json` |
| Prediction of the seven findings with CVSS | F-003 10.0 · F-005 10.0 · F-007 8.7 · F-001 8.3 · F-006 8.1 · F-008 7.9 · F-004 7.0 | `work/findings.json` |
| "Ledger check: refunds ≤ paid" | F-006 report prints `refunded 2000.00 > paid 1000.00` | `work/findings/F-006/report.md` |
| "Cross-finding dedupe before filing" | 8 → 7 | run output |
| "Owner routing + retest on fix" | 7 owners; `7 retested, 0 now fixed, 7 still open` | `python3 run.py retest` |
| "13 endpoints mapped without a spec" | no spec is read; the spec is *generated* | `work/openapi.generated.json` |
| "Test only what moved after a deploy" | 3-route deploy ⇒ 17 requests vs 39, 11 deferred | `run.py diff` + `scan --changed-only` |
| "One ticket per finding, SARIF + Markdown" | `REPORT.md` + `report.sarif` (7 results) | `work/` |
| "Standard library only" | no third-party runtime imports | `requirements.txt`, imports |

## FIX 1 — severity is additive, not multiplicative

- **Deck:** `CVSS floor × business multiplier`
- **Code:** `dast/report/severity.py` — `max(cvss_floor, 0) + sum(modifier points)`, capped at
  10.0, with a design note explaining that multipliers saturate (a 7.5 unauthenticated
  PII export would exceed 10 and the ranking would flatten).
- **What a judge sees:** `work/findings/F-006/report.md` →
  `CVSS floor 6.2 + 1.5 (money_movement) + 0.4 (write_operation) = 8.1`.
- **Replace with:** `CVSS floor + additive business modifiers, capped at 10.0`

## FIX 2 — "negative control on every test" is 4 of 7

| Finding | Class | `negative_control` in capsule |
|---|---|---|
| F-001 | BOLA | present (`path/status/expected/passed`) |
| F-003, F-004, F-005 | unauthenticated exposure | present |
| F-006 | double refund | **null** |
| F-007 | skipped payment | **null** |
| F-008 | fare tampering | **null** |

Route-driven findings do run a control (`dast/verify/engine.py::negative_control`: request
an object that must not exist; a 200 there voids the finding). Logic findings are proven
by the ledger invariant instead — which is stronger than a control, but it is **not** a
negative control, and the capsule says so honestly.

- **Replace with:** `Negative control on every route-driven test; logic findings must close
  a ledger invariant (refunded ≤ paid)`

## FIX 3 — no model sits in the decision path today

- **Deck:** "Agents decide what changed and what to test. Deterministic code decides what
  is actually real."
- **Code:** `dast/__init__.py` — "Nothing in here needs an LLM." The planner is a rule
  engine (`pipeline.plan_tests`) over an enum of 16 tests; `dast/attacks/registry.py` is
  documented as "the enum-constrained surface an LLM planner is allowed to return". The
  LLM is a *seam*, not a call.
- **Why it matters:** it is also the strongest safety argument — nothing that sends a
  request can be talked into it.
- **Replace with:** `The planner picks from an enum of 16 tests; deterministic code decides
  what is actually real.` (keep "agentic" for the loop, not for the decision)

## FIX 4 — roadmap numbers next to today's numbers

| Deck (plan section) | Today | Safer wording |
|---|---|---|
| W1 "delta run: max 5 requests, under 5 s" | 17 requests, 1.1 s on a 3-route deploy | `delta run: 17 requests / 1.1 s today → target ≤5 requests` |
| W2 "11 of 16 tests, 5 classes" | 5 implemented, 11 planned | `5 of 16 implemented today → 11 by 10 Dec` |
| W3 "p50 under 10 min over 10 runs" | not measured yet | keep — it is clearly a target |
| W4 "0 guard violations on staging" | 0 on the bundled target; staging not run | keep, but say `bundled target` |

## Video alignment

The Hinglish narration already avoids all four traps. Two lines to keep out of the take:

- ❌ "negative control har test par hai" → ✅ "route-driven test par negative control,
  logic findings ledger arithmetic se prove hote hain"
- ❌ "AI agent decide karta hai" → ✅ "planner enum se chunta hai, verifier deterministic hai"
