# Video script — Hinglish narration (2:40)

Same shot list as `deck/VIDEO_SCRIPT.md`; sirf bolne ki language Hinglish hai. Technical
words — findings, requests, audit chain, allowlist, deferred — English mein hi rakhe
hain, kyunki judge wahi term slide par dekhega. Numbers wahi hain jo
`bash deck/video/verify_numbers.sh` assert karta hai.

**Recording se pehle:** `bash deck/video/prepare.sh` → `bash deck/video/verify_numbers.sh`
→ last line "You are clear to record." aana chahiye. Slide 1 par `112` ko `228` karna
mat bhoolna.

---

### Beat 1 — 0:00–0:12 · Hook

**Screen:** `python3 run.py all --approve-writes` ka result, findings block.

**Bolna:**

> "Yeh ek DAST scanner hai jo CI ke liye bana hai. API map karta hai, dekhta hai kya
> change hua, sirf wahi attack karta hai — aur har finding ko arithmetic se prove karta
> hai, model ke opinion se nahi. Saat findings, untees requests, teen point nau second."

**Caption:** `7 verified findings · 39 requests · 3.9 s · exit 0`

---

### Beat 2 — 0:12–0:38 · Run aur inventory

**Screen:** command live type karo, 4 second ka wait cut karo, inventory table par ruko.
Mouse se `9 active, 1 shadow, 3 zombie` par point karo, phir `OWNER` column par.

**Bolna:**

> "Ek command, chaar second — na pip install, na API key. Discovery se inventory banti
> hai, aur har endpoint ko label milta hai: active, shadow ya zombie. Shadow matlab
> traffic mein hai par kisi bundle mein nahi; zombie matlab deploy hai par koi call nahi
> kar raha. Har row ke saath owner aur recommendation, kyunki jis endpoint ka owner nahi
> hota, wo fix nahi hota."

**Caption:** `discovery → classify → plan → attack → verify → report`

---

### Beat 3 — 0:38–1:02 · Finding khud ko prove karta hai

**Screen:**

```bash
sed -n '1,22p' work/findings/F-006/report.md
```

Pehle CVSS line par point karo, phir **Impact** ki yeh line:

```
refunded 2000.00 > paid 1000.00: the endpoint created money
```

**Bolna:**

> "Finding model ka guess nahi hai. Yeh double refund hai: scanner ne money flow chalaya,
> ledger wapas padha, aur do numbers compare kiye. Do hazaar refund hua jabki ek hazaar hi
> paid tha — yeh opinion nahi, arithmetic hai. Aur wahi numbers replayable capsule mein
> hain, to koi bhi proof dobara chala sakta hai."

**Caption:** `verified by invariant, not by judgement`

---

### Beat 4 — 1:02–1:22 · Safety ka chokepoint

**Screen:** `python3 run.py guard-demo` → `8/8 out-of-scope attempts refused, 2/2 in-scope
requests allowed`, phir `chain intact`.

**Bolna:**

> "Har request ek hi allowlist se guzarti hai, jise scanner bypass nahi kar sakta. Aath
> fresh out-of-scope attempts, aath refusals — redirect, scheme swap, path traversal, sab
> andar. Aur do in-scope requests phir bhi pass hui: jo guard sab kuch block kar de, wo
> evidence nahi hota. Audit log hash-chained hai."

**Caption:** `0 requests outside scope · hash-chained audit`

---

### Beat 5 — 1:22–1:58 · "Real-time" ka matlab

**Screen:**

```bash
cat deck/video/event.json
python3 run.py diff --deploy-event deck/video/event.json --out work-delta
python3 run.py scan --out work-delta --changed-only --approve-writes
```

Point karo: `touched 3 changed path(s); 3 route(s) to test first` →
`2 test target(s) kept, 11 deferred` → `"sent": 17` → do findings.

**Bolna:**

> "Asli baat yahi hai — isliye yeh CI tool hai, weekly scan nahi. CI ek deploy deta hai:
> commit, service, teen changed routes. Wahi idempotency key dobara aaye to retried
> webhook phir se run nahi karta. Scanner sirf wahi retest karta hai jo move hua — untees
> ki jagah satrah requests, teen point nau ki jagah ek point ek second. Aur jo test nahi
> kiya wo bolta bhi hai: gyarah test targets deferred, chup-chaap drop nahi. Un routes
> par jo do findings thi, wo phir bhi report hoti hain."

**Caption:** `17 vs 39 requests · 1.1 s vs 3.9 s · 11 deferred, never silenced`

---

### Beat 6 — 1:58–2:12 · Loop band hota hai

**Screen:** `python3 run.py retest` → `7 retested, 0 now fixed, 7 still open`.

**Bolna:**

> "Retest har capsule ko live target par dobara chalata hai. Unchanged deployment par
> sach yahi hai — still open, zero fixed. Aur point bhi yahi hai: jab fix ship hoga,
> yahin green ho jayega, per finding — poore scan ke liye nahi."

---

### Beat 7 — 2:12–2:26 · Team ko kya milta hai

**Screen:** `work/REPORT.md` ka head, phir SARIF ka count.

**Bolna:**

> "Repo mein aata hai: ticket-shaped report har finding ke owner ke saath, SARIF file saat
> results ke saath, findings JSON, aur har proof ka replayable capsule."

**Caption:** `REPORT.md · report.sarif (7) · findings.json · capsules`

---

### Beat 8 — 2:26–2:40 · Close, imaandaari se

**Screen:** repo root, cursor command list ke neeche.

**Bolna:**

> "Jo bhi aapne dekha, wo bundled target par chala — koi external host touch nahi hua.
> Solah tests catalogued hain, paanch implemented, baaki silence tests ke saath stubbed.
> Agla step: yahi loop ek staging platform par, published deploy-to-finding time ke saath.
> Repo public hai — ek command se chalta hai."

**Caption:** `github.com/Rohit4507/Agentic-DAST · MIT · no pip install, no model call`

---

## Bolne ka tareeka

- Speed: ~2.5 shabd per second. Numbers ke pehle chhota pause — judge ko padhne ka time do.
- Har beat ke shuru mein 0.5 s silence, aakhir mein 2 s — cut lagane ke liye.
- Numbers ko utha ke mat bolo ("saat findings" nahi, screen par `7` hai to bhi "saat" hi
  bolna hai, par us waqt mouse `7` par ho).
- Yeh mat bolna: "AI agent API hack karta hai", "production-ready", "kisi bhi API par
  kaam karta hai", "real platforms par validated", "30 findings".
- Do specific traps (dekho `deck/DECK_AUDIT.md`): ❌ "negative control har test par hai"
  (hai 4 of 7 — route-driven par; logic findings ledger arithmetic se prove hote hain) aur
  ❌ "AI agent decide karta hai" (planner enum se chunta hai; verifier deterministic hai).
- Honest line (Beat 8) ko mat kaatna — wahi line credibility deti hai.

## 60-second cut (Hinglish)

1. `work/REPORT.md` ki findings table — "Saat findings, teen point nau second mein." (8 s)
2. `F-006` report — "Do hazaar refund, ek hazaar paid — yeh arithmetic hai, opinion nahi." (15 s)
3. `guard-demo` — "Aath out-of-scope attempts, aath refusals." (10 s)
4. deploy-scoped run — "Sirf jo badla: satrah requests, untees ki jagah; gyarah deferred." (15 s)
5. Close — "Bundled target par chala, koi external host nahi. Repo public hai." (12 s)

## 90-second cut (Hinglish)

Beat 1 → 3 → 4 → 5 → 8. Matlab: proved, safe, incremental, honest.
