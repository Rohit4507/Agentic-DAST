# Screen recording — step by step

Do this in order. Total time: ~10 min setup, ~25 min recording, ~30 min editing.
Target length **2:40** (see `deck/VIDEO_SCRIPT.md` and the Hinglish version).

---

## A. Setup (once)

1. **Get the code and the target up.**
   ```bash
   cd Agentic-DAST && git pull
   bash deck/video/prepare.sh          # resets work/, starts the target on :8080, writes the event
   bash deck/video/verify_numbers.sh   # must end: "You are clear to record."
   ```
   If the last line is not there, fix that first — do not record a number you have not seen.

2. **Terminal.** Dark theme, font 18–20 pt, 118 columns so no line wraps, prompt short
   (`PS1='$ '`), scrollback cleared. Window capture (not full screen) so a stray
   notification cannot appear.

3. **Two panes.** Left: target server log (started by `prepare.sh`, never typed into).
   Right: your demo shell. The demo shell is the only thing you interact with on camera.

4. **Recorder.** OBS: Canvas 1920×1080, Output 30 fps, Encoder x264, CQ 20, format mp4,
   hotkey `F9` start/stop. Add one source: **Window Capture** of the terminal, then
   right-click → Transform → Fit to screen.
   QuickTime (macOS): File → New Screen Recording, then crop in the trim view.

5. **Machine hygiene.** Notifications off (Focus/Do Not Disturb), browser closed, desktop
   icons hidden, Slack/Teams quit. If a popup lands mid-take, throw the take away.

6. **Audio.** Record narration separately in Audacity (mono, 44.1 kHz) with the script on
   a second screen. Silent room, mic 15 cm away, -12 dB peaks, one sentence per breath.

---

## B. Record — one take per beat (F9 … F9)

Record the beats **out of order** if it helps: do the easy ones first (2, 6, 7), the
risky one (5) last, when you are warm. Keep each take 5–10 s longer than needed.

| Take | Beat | Type this | Point the mouse at | Say (see script) |
|---|---|---|---|---|
| T1 | 1 + 2 | `clear` then `python3 run.py all --approve-writes` | `13 endpoints: 9 active, 1 shadow, 3 zombie`, then `OWNER` column | hook + inventory |
| T2 | 3 | `sed -n '1,22p' work/findings/F-006/report.md` | `refunded 2000.00 > paid 1000.00: the endpoint created money` | arithmetic, not opinion |
| T3 | 4 | `python3 run.py guard-demo` | `8/8 out-of-scope attempts refused, 2/2 in-scope requests allowed` | the chokepoint |
| T4 | 5 | `cat deck/video/event.json` → `python3 run.py diff --deploy-event deck/video/event.json --out work-delta` → `python3 run.py scan --out work-delta --changed-only --approve-writes` | `3 route(s) to test first` → `2 test target(s) kept, 11 deferred` → `"sent": 17` | incremental run |
| T5 | 6 | `python3 run.py retest` | `7 retested, 0 now fixed, 7 still open` | the loop closes |
| T6 | 7 | `sed -n '1,22p' work/REPORT.md` then the SARIF count command | the findings table, then `7 SARIF results` | artefacts |
| T7 | 8 | `clear`, land on repo root | nothing — end card | honest close |

Rules during takes:

- **Do not type fast.** One command, then stop your hands. Typing races look amateur.
- **Cut the wait, not the number.** The 4 s run: let it start, cut, land on the finished
  output. Never speed up footage that shows a number.
- **Mouse, not "here".** Move the pointer to the exact line you are talking about.
- If a take goes wrong, stop, run `bash deck/video/prepare.sh` **only if** the state is
  dirty, and re-record that take. `work/` reset changes the audit count back to 47.

---

## C. Edit

7. **Order:** T1, T2, T3, T4, T5, T6, T7 → 8 beats, ~2:40 at natural pace.
8. **Cut gaps** to 0.4–0.6 s between sentences. Keep 2 s of tail on the last beat.
9. **Narration:** lay the Hinglish track on top. If a beat runs long, trim the footage,
   not the sentence with the number in it.
10. **Captions:** one per beat, exactly as in the script (e.g. `17 vs 39 requests · 1.1 s
    vs 3.9 s · 11 deferred, never silenced`).
11. **Zoom 1.2×** on the four anchor numbers (7 findings, 8/8, 17 vs 39, 7 retested) for
    1–1.5 s each. Nothing else.
12. **Music:** none, or a bed at -28 dB. Judges watch on laptop speakers.

---

## D. Export and hand in

13. H.264 mp4, 1080p30, AAC 128 kbps, loudness -16 LUFS, under 200 MB.
    Name: `Enxapse_Agentic-DAST_demo.mp4`.
14. Watch the whole thing once with the deck open next to it: every number on screen must
    match the deck. The deck says **228 tests** — if a take still shows 112, the take is
    stale (regenerate: `python3 deck/make_deck.py`).
15. Confirm the last 10 seconds still carry the honest line: *everything ran against the
    bundled target, no external host touched.*
16. Upload to Drive, set "anyone with the link can view", drop the link in the submission
    form next to the PDF.

---

## If you have only 60 seconds

Three shots: `work/REPORT.md` findings table (5 s) → `F-006` arithmetic line (15 s) →
`guard-demo` 8/8 (10 s) → deploy-scoped `17` vs `39` (15 s) → close card (10 s).

## Failure playbook

| Problem | Fix |
|---|---|
| `target not answering` | `bash deck/video/prepare.sh`, check `/tmp/dast-target.log` |
| audit count prints 60 not 47 | `work/` was not reset — `prepare.sh`, re-verify, re-record |
| elapsed prints 4.3 s | keep it, say "about four seconds"; never edit a printed number |
| a popup appears | discard the take, re-record it |
| terminal line wraps | widen window or 16 pt; wrapped JSON reads as a broken tool |
