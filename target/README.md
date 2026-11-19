# Mock travel API — deliberately vulnerable

> ⚠️ **This application is insecure on purpose.** It exists so the DAST harness has a
> target with known, planted bugs that can be verified end to end without touching any
> real system. It binds to loopback only and refuses a public bind unless
> `ALLOW_UNSAFE_BIND=1` is set. Never deploy it.

## Run it

```bash
python -m target.app --port 8080          # tokens: tok-agency-a, tok-agency-b
python -m target.capture                  # record normal journeys -> captures/*.har
python -m target.make_traffic             # regenerate the 30-day gateway log
```

## What is planted, and what is correct

Two agencies (`AGENCY-A`, `AGENCY-B`), three seeded bookings, a hold → pay → confirm →
cancel → refund flow, and a per-booking ledger.

| Class | Endpoint | Behaviour |
|---|---|---|
| **BOLA** | `GET /api/booking/{id}` | authenticates, never checks ownership |
| **Zombie** | `GET /api/v1/booking/{id}` | v1 contract, **no auth**, leaks traveller PII |
| **Zombie** | `GET /api/old/agency/{id}/summary` | retired route, no auth, leaks booking counts and value |
| **Zombie** | `GET /api/test/debug` | debug route in "production", exposes env + flags |
| **Shadow** | `GET /api/internal/agency/{id}/export` | in use by an internal tool, in no bundle, **no auth**, dumps bookings |
| **Logic** | `POST /api/refund` | refunds a booking more than once |
| **Logic** | `POST /api/confirm` | reaches `CONFIRMED` with zero payment |
| **Logic** | `POST /api/rebook` | writes a client-supplied `amount` into the fare |

Correct on purpose — these are the false-positive traps:

| Endpoint | Behaviour |
|---|---|
| `GET /api/bookings` | 401 without a token; filtered to the caller's agency |
| `GET /api/ledger/{id}` | ownership enforced → `403` cross-tenant |
| `GET /api/booking/{id}` (unknown id) | `404`, so a negative control is meaningful |
| `GET /api/v1/booking/{id}` (unknown id) | `404`, same reason |
| `POST /api/refund/bulk` | destructive and **deny-listed** in `scope.json` |

The six happy-path routes are hit in `traffic/gateway_30d.jsonl`; the legacy ones are
not, which is what makes them zombies. `/api/internal/...` appears in the gateway log
but in no JavaScript bundle, which is what makes it a shadow API.

## Why a mock target is in a security repo

Three reasons, all practical:

1. **Reproducibility.** Every claim in the README can be re-derived in one command, by
   a reviewer, with no credentials and no network.
2. **Precision is testable.** Correct-by-construction endpoints let the test-suite
   assert *silence* — that the verifier does not report the `403` on `/api/ledger`.
3. **The engagement inputs exist.** HAR journeys, a 30-day gateway log, a JS bundle and
   an asset-ownership map are all provided inputs in the real problem statement. This
   target supplies all four so the inventory stage can be exercised honestly.
