# Submission video — shot list, script, and recording runbook

**Verdict up front: record the video now. Do not write more product code first.**
Every claim the deck makes is already demonstrable in ~2m40s of screen capture, and more
features would only make the video longer, not more convincing. The one thing that would
make the submission stronger — a run against a third-party API — needs staging access,
not code.

Hinglish narration: `deck/VIDEO_SCRIPT_HINGLISH.md` (same shot list, same timings).

Everything below is measured, not estimated: `bash deck/video/verify_numbers.sh` re-runs
the whole sequence and asserts each figure against the deck.

---

## 0. Before you press record (10 minutes)

### 0.1 Fix two numbers on the deck

| Slide | Reads | Must read | Why |
|---|---|---|---|
| 1 (cover) | `TESTS PASSING 112` | **`TESTS PASSING 228`** | `python3 -m unittest discover -s tests` prints `Ran 228 tests … OK`. A judge can run it. |
| 3–4 | `11 of 16 tests implemented` | keep, but label it **roadmap**: "5 of 16 implemented today → 11 by 24 Dec" | `python3 run.py catalogue` prints 5 `implemented`, 11 `planned`. The roadmap text is honest only if it reads as a target. |

Every other figure already matches: 7 findings · 2 critical / 5 high · 13 endpoints
(9/1/3) · 39 requests · 0 denied · 81 of 120 left · 47 audit entries · 3.9 s · 8/8
out-of-scope refused · 8 raw hits → 7 findings · 16 catalogued.

### 0.2 Prepare the machine

```bash
bash deck/video/prepare.sh        # resets work/, starts the bundled target, writes the deploy event
bash deck/video/verify_numbers.sh # every number the deck claims, asserted against a real run
```

You want the last line to say **"You are clear to record."** It leaves exactly the state
the video needs on disk: `work/` (full run, 7 findings) and `work-delta/` (deploy-scoped
run). Do **not** reset between verifying and recording.

### 0.3 Capture settings

- 1920×1080, 30 fps. Terminal font 18–20 pt, dark theme, no ligatures, wide enough that
  no line wraps (`118` columns).
- Two panes: **left** = target (`python3 -m target.app --port 8080`, left alone, never
  typed into on camera), **right** = the demo shell.
- Notifications off, browser closed, desktop icons hidden, no other tabs visible.
- Record narration **separately** and lay it over the capture. One bad "um" is worth a
  re-record of 40 seconds of audio, not of the run.
- Keep 2 s of silence at the head and tail of each beat so cuts are clean.

### 0.4 Rules for what you say

Say: scanned, proven, allowlist, audit chain, deferred, replayable capsule.
Never say: "AI agent hacks your API", "production-ready", "finds bugs in any API",
"validated on real platforms", "30 findings", or any number you did not see print.
Two traps from `deck/DECK_AUDIT.md`: "negative control on every test" (it is 4 of 7 —
route-driven only; logic findings close a ledger invariant instead) and "the agent decides
what to test" (the planner picks from an enum; a rule engine decides).
One sentence of scope honesty ("everything here runs against the bundled target, no
external host is touched") buys more credibility than any adjective.

---

## 1. The film — 2:40, eight beats

Layout: full-screen terminal. Cut, don't scroll. Point with the mouse, never with "over
here somewhere".

### Beat 1 — 0:00–0:12 · Hook

**Screen:** `python3 run.py all --approve-writes` already finished; findings block visible.

> **Narration:** "This is a DAST scanner built for CI. It maps an API, decides what
> changed, attacks only that, and proves every finding with arithmetic instead of a
> model's opinion. Seven findings, thirty-nine requests, three point nine seconds."

**Caption:** `7 verified findings · 39 requests · 3.9 s · exit 0`

### Beat 2 — 0:12–0:38 · The run and the inventory

**Do:** `clear` → type the command live → cut the 4 s wait → land on the inventory table.

**Point at:** `13 endpoints: 9 active, 1 shadow, 3 zombie`, then the `OWNER` column.

> **Narration:** "One command, four seconds, no pip install and no API key. Discovery
> produces an inventory, and every endpoint is labelled by what it *is*: active, shadow —
> in traffic but missing from every bundle — or zombie, still deployed with nothing
> calling it. Each row carries an owner and a recommendation, because an unowned endpoint
> never gets fixed."

**Caption:** `discovery → classify → plan → attack → verify → report`

### Beat 3 — 0:38–1:02 · A finding proves itself

**Do:**

```bash
sed -n '1,22p' work/findings/F-006/report.md
```

**Point at:** the CVSS breakdown line, then this sentence in **Impact**:

```
the ledger shows 2 successful refunds totalling 2000.00 against 1000.00 paid
... refunded 2000.00 > paid 1000.00: the endpoint created money
```

> **Narration:** "A finding is not a model's hunch. This is a double refund: the scanner
> executed the money flow, read the ledger back, and compared two numbers. Two thousand
> refunded against one thousand paid is not an opinion — it is arithmetic, and the same
> numbers are in a replayable capsule, so a human can re-run the proof."

**Caption:** `verified by invariant, not by judgement`

### Beat 4 — 1:02–1:22 · The safety chokepoint

**Do:**

```bash
python3 run.py guard-demo
```

**Point at:** `8/8 out-of-scope attempts refused, 2/2 in-scope requests allowed`, then
`audit: … chain intact`.

> **Narration:** "Every request goes through one allowlist that the scanner cannot reach
> around. Eight fresh out-of-scope attempts: eight refusals, including a redirect, a
> scheme swap and a path traversal. The two in-scope requests still pass — a guard that
> blocks everything is not evidence of anything. And the audit log is hash-chained."

**Caption:** `0 requests outside scope · hash-chained audit`

### Beat 5 — 1:22–1:58 · What "real-time" actually means

**Do:**

```bash
cat deck/video/event.json
python3 run.py diff --deploy-event deck/video/event.json --out work-delta
python3 run.py scan --out work-delta --changed-only --approve-writes
```

**Point at, in order:** `touched 3 changed path(s); 3 route(s) to test first`,
`deploy priority: … 2 test target(s) kept, 11 deferred`, then the guard line
`"sent": 17` and the two findings it kept.

> **Narration:** "This is the part that makes it a CI tool rather than a weekly scan. CI
> hands over a deploy: a commit, a service, three changed routes. Share the idempotency
> key and a retried webhook does not re-run. Here the scanner retests what moved —
> seventeen requests instead of thirty-nine, one point one seconds instead of three point
> nine — and it says what it *didn't* test: eleven test targets deferred, not silently
> dropped. The two findings on those routes are still reported."

**Caption:** `17 vs 39 requests · 1.1 s vs 3.9 s · 11 deferred, never silenced`

### Beat 6 — 1:58–2:12 · The loop closes

**Do:**

```bash
python3 run.py retest
```

**Point at:** `7 retested, 0 now fixed, 7 still open`.

> **Narration:** "Retest replays each capsule against the live target. On an unchanged
> deployment the honest answer is 'still open, zero fixed' — and that is the point: when a
> fix does ship, this is where it turns green, per finding, not per scan."

### Beat 7 — 2:12–2:26 · The artefacts a team consumes

**Do:**

```bash
sed -n '1,22p' work/REPORT.md
python3 -c "import json;print(len(json.load(open('work/report.sarif'))['runs'][0]['results']),'SARIF results')"
```

> **Narration:** "What lands in the repo: a ticket-shaped report with an owner per
> finding, a SARIF file with seven results for code scanning, a JSON findings set, and a
> replayable capsule for each proof."

**Caption:** `REPORT.md · report.sarif (7) · findings.json · capsules`

### Beat 8 — 2:26–2:40 · Close, honestly

**Do:** end on the repo root, cursor under the command list.

> **Narration:** "Everything you saw ran against the bundled target — no external host was
> touched. Sixteen tests are catalogued, five implemented, the rest stubbed with silence
> tests. The next step is the same loop against a staging platform, with a published
> deploy-to-finding time. The repo is public and runs with one command."

**Caption:** `github.com/Rohit4507/Agentic-DAST · MIT · no pip install, no model call`

---

## 2. The exact sequence, copy-paste

```bash
bash deck/video/prepare.sh
bash deck/video/verify_numbers.sh

python3 run.py all --approve-writes                                  # beats 1–2
sed -n '1,22p' work/findings/F-006/report.md                         # beat 3
python3 run.py guard-demo                                            # beat 4
cat deck/video/event.json                                            # beat 5
python3 run.py diff --deploy-event deck/video/event.json --out work-delta
python3 run.py scan --out work-delta --changed-only --approve-writes
python3 run.py retest                                                # beat 6
sed -n '1,22p' work/REPORT.md                                        # beat 7
python3 -c "import json;print(len(json.load(open('work/report.sarif'))['runs'][0]['results']),'SARIF results')"
python3 run.py catalogue                                             # beat 8, optional
```

Expected lines to look for (these are the ones `verify_numbers.sh` asserts):

| Command | Line |
|---|---|
| `all` | `13 endpoints: 9 active, 1 shadow, 3 zombie` · `8 raw hits -> 7 findings` · `"sent": 39` · `audit: 47 entries, chain intact` · `elapsed: 3.9s` |
| `F-006/report.md` | `refunded 2000.00 > paid 1000.00: the endpoint created money` |
| `guard-demo` | `8/8 out-of-scope attempts refused, 2/2 in-scope requests allowed` |
| `diff` | `touched 3 changed path(s); 3 route(s) to test first` |
| `scan --changed-only` | `2 test target(s) kept, 11 deferred` · `"sent": 17` · `elapsed: 1.1s` |
| `retest` | `7 retested, 0 now fixed, 7 still open` |
| `catalogue` | `dast-agent 0.1.0 — test library (16 tests)` |

---

## 3. When something goes wrong

| Symptom | Do this |
|---|---|
| `target not answering` | `bash deck/video/prepare.sh` again; check `/tmp/dast-target.log` |
| Elapsed prints 4.3 s instead of 3.9 | Leave it. Say "four seconds on this laptop". Never edit the number. |
| A run dies mid-beat | Stop the take, `prepare.sh`, re-record that beat only, splice. |
| Audit count higher than 47 | `work/` was not reset — re-run `prepare.sh`, then `verify_numbers.sh`. |
| Terminal line wraps | widen the window or drop to 16 pt; wrapped JSON looks like a broken tool. |
| You have only 60 s of slot | use the cut below; do not speed-ramble the full script. |

---

## 4. 90-second and 60-second cuts

**90 s:** beats 1 → 3 → 4 → 5 → 8 (hook, proof, guard, deploy delta, close).
That is the whole argument: *proven, safe, incremental*.

**60 s:** three shots only —
`work/REPORT.md` findings table (5 s) → `F-006` arithmetic line (15 s) →
`guard-demo` 8/8 (10 s) → deploy-scoped `17` vs `39` (15 s) → close card (10 s).

---

## 5. After the video

- If any code changes after recording, re-run `bash deck/video/verify_numbers.sh`; a
  changed number invalidates the take.
- If you correct the deck (0.1), upload the corrected PDF to Drive *before* posting the
  video, so the two artefacts agree.
- Keep the raw capture. If a judge asks "show me F-006 again", you want the uncut file.
