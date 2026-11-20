# Real-world plan

**Question this document answers:** the tool runs, but does it work on an API it did
not write? Version 1 did not — it was pinned to the mock's vocabulary and would have
reported "0 findings" against a real platform. This records what was fixed, what is
measured, and what is still open.

## Where version 1 was pinned

| Layer | Version 1 | Real-world effect |
|---|---|---|
| Flow paths | `FlowPaths()` defaults in `plan_tests` / `execute_plan` | logic tests never planned on a foreign API |
| Request bodies | `{"booking": id, "amount": n}` literals | 422/400 on any other schema |
| Object identity | `identity_field="bookingId"`, top-level only | cross-tenant match impossible → no BOLA finding |
| Tenant boundary | `boundary_field="agencyId"`, top-level only | boundary crossing unprovable |
| Agency discovery | 4 hard-coded probe paths, top-level keys | roles unresolved → cross-tenant tests skipped |
| Ledger | `GET /api/ledger/{id}` | invariants unprovable → logic findings void |
| Bundle harvest | `/api/` prefix only | all `/v2/` routes invisible to the inventory |
| BOLA exclusions | `/v1/`, `/v2/`, `/old/`, `/test/` | a `/v2/`-based API excluded *in full* |

Every one of those was a string literal in the scanner — i.e. the tool knew one
customer.

## What is built

1. **`dast/profile.py` — the target profile.** Paths, request-body templates, identity
   and boundary field paths (dotted, with synonym ladders), agency probes, ledger
   adapter and field map, BOLA exclusions, bundle prefixes, and the noun the target uses
   ("booking" / "order"). Validation is fail-closed: unknown keys, unknown placeholders
   and non-absolute paths are fatal, because a typo'd `boundary_field` would otherwise
   degrade into "no cross-tenant findings" — a silent pass.
2. **`dast/fields.py` — dotted resolution.** `data.order.id`, list indexes, money as
   `"Rs 1,234.50"`, and an identity comparison that tolerates `8842` vs `"8842"`.
3. **`dast/verify/ledger_source.py` — portable money proof.** `http` (endpoint + field
   map + per-row map), `fixture` (JSON keyed by id, JSON array, or CSV export), `none`.
   An unreadable ledger **voids** the finding; it never assumes the invariant held.
4. **Scope-aware open.** A profile naming paths the allowlist does not cover fails at
   engagement open, with the paths listed, instead of failing silently mid-run.
5. **Retest resolves nested identity.** Standing up target2 surfaced a real bug:
   `replay_capsule` looked the stored `identity_field` up at the top level only, so
   every nested target would have been reported **"fixed" on the first retest**. It now
   resolves by dotted path with a synonym ladder, and a reworded response is no longer
   mistaken for a fix (`tests/test_verify.py::TestReplayNestedIdentity`).
6. **`target2/` — a second, deliberately different target.** `/v2/` prefixes, nested
   payloads, `tenant`, `value`/`state`, `settlements`/`reversals`, statement endpoint.
   Its capture/gateway fixtures are generated (`python -m target2.fixtures --out target2`)
   so they never go stale.

## What is measured

| | mock (`target/`) | target2 (`target2/`) |
|---|---|---|
| Profile | built-in defaults (no `profile` key) | `profiles/target2.json` |
| Endpoints | 13 (9 active / 1 shadow / 3 zombie) | 10 (8 / 1 / 1) |
| Verified findings | 7 (2 critical, 5 high) | 5 (1 critical, 4 high) |
| Classes | BOLA, double refund, skipped payment, fare tampering, 3× exposure | BOLA, double refund, skipped payment, fare tampering, exposure |
| Cross-tenant evidence | `bookingId` / `agencyId` | `data.order.id` / `data.order.tenant` |
| Ledger | `GET /api/ledger/{id}` | `GET /v2/orders/{id}/statement`, mapped |
| Requests / audit entries | 39 / 47 | 34 / 42 |
| Guard | 0 denied, 81 of 120 left | 0 denied, 86 of 120 left |
| Elapsed | 3.89 s | 3.26 s |

The mock's numbers are **unchanged** from version 1 — the profile layer is additive, and
`profiles/mock.json` is asserted equal to the built-in defaults so the two cannot drift.

An **incremental** run is now a different measurement, because the deploy event says what
to retest. Same mock, event naming three changed paths (`/api/refund`, `/api/rebook`,
`/api/pay`), `python run.py scan --changed-only`:

| | full run | deploy-scoped run |
|---|---|---|
| Requests | 39 | 17 |
| Audit entries | 47 | 27 |
| Findings | 7 | 2 (double refund 8.1, fare tampering 7.9) |
| Test targets deferred | 0 | 11 |
| Elapsed | 3.88 s | 1.13 s |

The two findings are exactly the ones whose routes the deploy touched; the other five
belong to routes that did not change and are reported as deferred, not as absent.

`tests/test_genericity.py` also runs target2 **with the mock's profile**: the
identity-dependent tests go quiet, route-driven exposure still fires. Same target, same
traffic, same code — only vocabulary changes. That isolates the cause and is the reason
the layer exists.

## What closed, and how it was proved

| # | Item | Evidence |
|---|---|---|
| 2 | `429` / `503` backoff with `Retry-After` | `dast/http.py` retry loop. A stub answering `429` + `Retry-After: 1` twice then `200` produces **3 audited requests, 3 budget-charged, 1 result** (`tests/test_transport.py::TestRetryOn429`). `Retry-After` is read as seconds *or* an HTTP-date; a single wait is capped by `--retry-max-wait`. Every attempt carries its own audit line with `attempt=N`, so a retry is never invisible. `500` is **not** retried — it is a broken host, not a busy one. |
| 4 | Token refresh hook | `dast/token_refresh.py` + `auth.refresh` in `scope.json`. One 401 triggers one refresh then one replay; the refresh request goes through the same guard; a failed refresh voids the request rather than raising. Secrets come from `env:` and are asserted absent from the audit log (`TestTokenRefresh`). |
| 5 | `--deploy-event` | `dast/deploy.py` + `run.py diff --deploy-event` + `scan --changed-only`. `sha` is the idempotency key: replaying a webhook does not re-run. Unknown keys, a missing `sha`, non-absolute bundle URLs and unparseable JSON are all exit 2 naming the field. `changed_paths` are templated and matched against `work/inventory.json`; anything unmatched is listed as *not yet inventoried* rather than silently dropped. |
| 7 | Bundle fetch over HTTP | `--bundle-url` / `bundle_urls` fetch through the scope-checked client: budget-charged, audited, refused if the host is out of scope (`exit 2`), and a bundle that yields zero routes prints the prefixes it searched instead of pretending nothing changed. |

A dead host is also now a hard failure rather than a clean report: a host answering `5xx`
to everything exits **2** with "target unreachable", and no `REPORT.md` / `findings.json`
is written (`tests/test_transport.py::TestDeadHost`). Zero findings from a silent host and
zero findings from a secure host must not be the same output.

## What is still open

| # | Item | Why it matters | Size |
|---|---|---|---|
| 1 | **A third-party target run** | the only honest proof. Needs a staging host + accounts. | depends on access |
| 3 | Connection reuse | one TLS handshake per request; at 100 ms RTT a 500-request run pays for it | ~half day |
| 6 | OpenAPI / Postman **ingest** | we generate a spec; we do not read one, so a documented API starts from zero inventory | 1 day |
| 8 | Credential rotation mid-run | a refresh path is assumed; refresh tokens and re-auth flows are not | 1 day |
| 9 | Multi-service deploy events | one event, one service; a platform deploy is many | 2 days |

Item 3 is the last piece of transport work and changes no finding. Item 6 is the widest
gap for a documented API. Item 1 is the one that cannot be substituted by anything above.

## Definition of done

1. Two structurally different targets, same classes found, one profile apart — **done**.
2. `profiles/mock.json` cannot drift from the built-in defaults — **done** (test).
3. Every vocabulary failure is loud: fatal at load, or a recorded skip reason — **done**.
4. Fail-closed preserved: unreadable identity / boundary / ledger ⇒ no finding, with a
   reason, never a guess — **done**.
5. Deck numbers labelled mock vs real; a real-target run recorded in `targets/proof.json`
   — **open**, gated on item 1.
6. A retry, a token refresh and a deploy-scoped run are each covered by a test that
   asserts the *counts* (requests sent, budget spent, audit lines) — **done**
   (`tests/test_transport.py`: 17 tests, `tests/test_deploy.py`: 32 tests).
