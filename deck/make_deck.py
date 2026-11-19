#!/usr/bin/env python3
"""Generate the 4-slide submission deck as a monochrome PDF, standard library only.

    python3 deck/make_deck.py
    -> deck/VOYAGEHACK4_Agentic_DAST_SUBMISSION.pdf

Every number printed here is one the pipeline actually produces. The run that
measured them is documented in deck/IMPLEMENTATION_PLAN.md.
"""

from __future__ import annotations

import zlib
from pathlib import Path

W, H = 960.0, 540.0
M = 56.0                                  # page margin
F1, F2, F3, F4 = "F1", "F2", "F3", "F4"   # Helvetica, Helvetica-Bold, Courier, Courier-Bold

# ------------------------------------------------------------------ metrics
_BASE = {32: 278, 33: 278, 34: 355, 35: 556, 36: 556, 37: 889, 38: 667, 39: 191,
         40: 333, 41: 333, 42: 389, 43: 584, 44: 278, 45: 333, 46: 278, 47: 278,
         58: 278, 59: 278, 60: 584, 61: 584, 62: 584, 63: 556, 64: 1015,
         91: 278, 92: 278, 93: 278, 94: 469, 95: 556, 96: 333,
         123: 334, 124: 260, 125: 334, 126: 584}
_BASE.update({c: 556 for c in range(48, 58)})

HELV = dict(_BASE)
HELV.update({ord(k): v for k, v in {
    "A": 667, "B": 667, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778, "H": 722,
    "I": 278, "J": 500, "K": 667, "L": 556, "M": 833, "N": 722, "O": 778, "P": 667,
    "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722, "V": 667, "W": 944, "X": 667,
    "Y": 667, "Z": 611, "a": 556, "b": 556, "c": 500, "d": 556, "e": 556, "f": 278,
    "g": 556, "h": 556, "i": 222, "j": 222, "k": 500, "l": 222, "m": 833, "n": 556,
    "o": 556, "p": 556, "q": 556, "r": 333, "s": 500, "t": 278, "u": 556, "v": 500,
    "w": 722, "x": 500, "y": 500, "z": 500}.items()})

HELVB = dict(_BASE)
HELVB.update({ord(k): v for k, v in {
    " ": 278, "!": 333, '"': 474, "#": 556, "$": 556, "%": 889, "&": 722, "'": 238,
    "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333, ".": 278, "/": 278,
    ":": 333, ";": 333, "<": 584, "=": 584, ">": 584, "?": 611, "@": 975,
    "A": 722, "B": 722, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778, "H": 722,
    "I": 278, "J": 556, "K": 722, "L": 611, "M": 833, "N": 722, "O": 778, "P": 667,
    "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722, "V": 667, "W": 944, "X": 667,
    "Y": 667, "Z": 611, "[": 333, "\\": 278, "]": 333, "^": 584, "_": 556, "`": 333,
    "a": 556, "b": 611, "c": 556, "d": 611, "e": 556, "f": 333, "g": 611, "h": 611,
    "i": 278, "j": 278, "k": 556, "l": 278, "m": 889, "n": 611, "o": 611, "p": 611,
    "q": 611, "r": 389, "s": 556, "t": 333, "u": 611, "v": 556, "w": 778, "x": 556,
    "y": 556, "z": 500, "{": 389, "|": 280, "}": 389, "~": 584}.items()})
HELVB.update({c: 556 for c in range(48, 58)})


def advance(font: str, size: float, text: str, tracking: float = 0.0) -> float:
    if font in (F3, F4):
        raw = 600 * len(text)
    else:
        table = HELVB if font == F2 else HELV
        raw = sum(table.get(ord(ch), 556) for ch in text)
    return raw * size / 1000.0 + max(0, len(text) - 1) * tracking


def wrap(text: str, font: str, size: float, width: float) -> list[str]:
    lines: list[str] = []
    cur = ""
    for word in text.split(" "):
        cand = word if not cur else cur + " " + word
        if advance(font, size, cand) <= width:
            cur = cand
            continue
        if cur:
            lines.append(cur)
        while advance(font, size, word) > width and len(word) > 1:
            cut = len(word)
            while cut > 1 and advance(font, size, word[:cut]) > width:
                cut -= 1
            lines.append(word[:cut])
            word = word[cut:]
        cur = word
    if cur:
        lines.append(cur)
    return lines


# ------------------------------------------------------------------ plumbing
FONT_SPECS = {
    F1: (b"Helvetica", b""),
    F2: (b"Helvetica-Bold", b""),
    F3: (b"Courier", b""),
    F4: (b"Courier-Bold", b""),
}


class PDF:
    def __init__(self) -> None:
        self.streams: list[bytes] = []
        self.boxes: list[tuple[int, float, float, float, float, str]] = []
        self.pages_created = 0

    def new_page(self) -> "Page":
        self.pages_created += 1
        return Page(self)

    def save(self, path: Path) -> None:
        n = len(self.streams)
        objs: dict[int, bytes] = {}
        page_nums = [7 + i for i in range(n)]
        content_nums = [7 + n + i for i in range(n)]
        kids = " ".join(f"{p} 0 R" for p in page_nums)
        objs[1] = b"<</Type /Catalog /Pages 2 0 R>>"
        objs[2] = f"<</Type /Pages /Kids [{kids}] /Count {n}>>".encode()
        for i, font in enumerate((F1, F2, F3, F4)):
            base, _ = FONT_SPECS[font]
            objs[3 + i] = (b"<</Type /Font /Subtype /Type1 /BaseFont /" + base +
                           b" /Encoding /WinAnsiEncoding>>")
        resources = (b"<</Font <</F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R>>>>")
        for i in range(n):
            objs[page_nums[i]] = (b"<</Type /Page /Parent 2 0 R /MediaBox [0 0 960 540] "
                                  b"/Resources " + resources + b" /Contents "
                                  + str(content_nums[i]).encode() + b" 0 R>>")
            objs[content_nums[i]] = (b"<</Length " + str(len(self.streams[i])).encode()
                                     + b" /Filter /FlateDecode>>\nstream\n"
                                     + self.streams[i] + b"\nendstream")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: dict[int, int] = {}
        for num in sorted(objs):
            offsets[num] = len(out)
            out += f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n"
        xref = len(out)
        count = max(objs) + 1
        out += f"xref\n0 {count}\n".encode() + b"0000000000 65535 f \n"
        for num in range(1, count):
            out += f"{offsets.get(num, 0):010d} 00000 n \n".encode()
        out += (f"trailer\n<</Size {count} /Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n").encode()
        path.write_bytes(bytes(out))


class Page:
    def __init__(self, pdf: PDF) -> None:
        self.pdf = pdf
        self.index = pdf.pages_created
        self.ops: list[str] = []

    @staticmethod
    def _esc(text: str) -> str:
        return (text.encode("cp1252", "replace").decode("latin-1")
                .replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)"))

    def text(self, x: float, top: float, s: str, font: str = F1, size: float = 10,
             gray: float = 0.0, tracking: float = 0.0, align: str = "left") -> None:
        if not s:
            return
        wid = advance(font, size, s, tracking)
        if align == "right":
            x -= wid
        elif align == "center":
            x -= wid / 2
        self.ops.append(f"{gray:.3f} g")
        tc = f" {tracking:.3f} Tc" if tracking else ""
        self.ops.append(f"BT /{font} {size:.2f} Tf{tc} 1 0 0 1 {x:.2f} {H - top:.2f} Tm "
                        f"({self._esc(s)}) Tj ET")
        self.pdf.boxes.append((self.index, x, top - size * 0.78, wid, size * 1.02, s))

    def para(self, x: float, top: float, width: float, s: str, font: str = F1,
             size: float = 10, leading: float = 14, gray: float = 0.0,
             max_lines: int | None = None) -> float:
        lines = wrap(s, font, size, width)
        if max_lines and len(lines) > max_lines:
            raise AssertionError(f"paragraph overflows {max_lines} lines: {s[:70]!r}")
        for i, line in enumerate(lines):
            self.text(x, top + i * leading, line, font, size, gray)
        return top + len(lines) * leading

    def hline(self, x1: float, x2: float, top: float, gray: float = 0.72, lw: float = 0.6) -> None:
        self.ops.append(f"{lw:.2f} w {gray:.3f} G {x1:.2f} {H - top:.2f} m {x2:.2f} {H - top:.2f} l S")

    def vline(self, x: float, top1: float, top2: float, gray: float = 0.85, lw: float = 0.6) -> None:
        self.ops.append(f"{lw:.2f} w {gray:.3f} G {x:.2f} {H - top1:.2f} m {x:.2f} {H - top2:.2f} l S")

    def rect(self, x: float, top: float, w: float, h: float, fill: float | None = None,
             stroke: float | None = None, lw: float = 0.7) -> None:
        y = H - top - h
        if fill is not None:
            self.ops.append(f"{fill:.3f} g {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")
        if stroke is not None:
            self.ops.append(f"{lw:.2f} w {stroke:.3f} G {x:.2f} {y:.2f} {w:.2f} {h:.2f} re S")

    def done(self) -> None:
        self.pdf.streams.append(zlib.compress("\n".join(self.ops).encode("latin-1"), 9))


INK, MID, SOFT, HAIR = 0.10, 0.42, 0.62, 0.86


def top_rule(p: Page) -> None:
    p.rect(0, 0, W, 4.5, fill=0.10)


def footer(p: Page, n: int, left: str = "Agentic Real-Time DAST") -> None:
    p.hline(M, W - M, 484, HAIR, 0.6)
    p.text(M, 504, left, F1, 8, SOFT)
    p.text(W - M, 504, f"github.com/Rohit4507/Agentic-DAST   ·   {n} / 4",
           F3, 7.5, SOFT, align="right")


def header(p: Page, kicker: str, title: str, sub: str) -> None:
    p.text(M, 50, kicker, F2, 8.5, 0.35, tracking=1.6)
    p.text(W - M, 50, "TBO.COM  ·  VOYAGEHACK 4.0", F1, 8, SOFT, tracking=1.2, align="right")
    p.hline(M, W - M, 64, HAIR)
    p.text(M, 108, title, F2, 25, INK)
    p.para(M, 132, W - 2 * M, sub, F1, 10.5, 15, MID, max_lines=2)


# ------------------------------------------------------------------ slide 1
def slide_cover(pdf: PDF) -> None:
    p = pdf.new_page()
    top_rule(p)
    p.text(M, 54, "TBO.COM   /   VOYAGEHACK 4.0   /   SECURITY HACKATHON 2026",
           F2, 8.5, 0.35, tracking=1.5)
    p.text(W - M, 54, "IDEA SUBMISSION ROUND", F1, 8, SOFT, tracking=1.2, align="right")
    p.hline(M, W - M, 70, HAIR)

    p.text(M, 152, "Agentic", F2, 50, INK)
    p.text(M, 208, "Real-Time DAST", F2, 50, INK)
    p.hline(M, 300, 226, INK, 2.2)
    p.text(M, 254, "Security agents that hunt vulnerabilities as the platform changes.", F1, 14, MID)

    p.para(M, 288, 528,
           "A change-triggered DAST loop over an undocumented travel API. It maps the surface, "
           "plans targeted tests, sends every request through one fail-closed guard, proves each "
           "hit with deterministic evidence, and labels zombie and shadow endpoints.",
           F1, 10, 15.5, 0.30, max_lines=3)

    p.rect(M, 356, 528, 108, fill=0.955)
    p.text(M + 16, 378, "VERIFIED RUN  ·  MOCK TARGET  ·  PYTHON 3.11", F2, 7, 0.40, tracking=1.3)
    rows = [
        ("$ python3 run.py all --approve-writes", F4, 0.15),
        ("dedupe     8 raw hits -> 7 findings", F3, 0.30),
        ("guard      39 checked, 0 denied, 39 sent   p95 1.3 ms", F3, 0.30),
        ("audit      47 entries, chain intact", F3, 0.30),
        ("elapsed    3.89 s", F3, 0.30),
    ]
    for i, (line, font, gray) in enumerate(rows):
        p.text(M + 16, 396 + i * 13.5, line, font, 8, gray)

    p.rect(632, 96, 272, 368, stroke=HAIR, lw=0.8)
    p.text(652, 120, "MEASURED, NOT CLAIMED", F2, 7, 0.40, tracking=1.3)
    stats = [
        ("7", "verified findings", "2 critical · 5 high"),
        ("13", "endpoints mapped", "9 active · 1 shadow · 3 zombie"),
        ("39", "requests audited", "0 denied · p95 1.3 ms"),
        ("112", "tests passing", "stdlib only · 2.1 s"),
        ("0", "dependencies", "and zero model calls"),
    ]
    for i, (num, label, note) in enumerate(stats):
        y = 140 + i * 63
        p.text(652, y + 26, num, F2, 27, INK)
        p.text(652, y + 40, label, F1, 9, 0.28)
        p.text(652, y + 52, note, F1, 7.6, SOFT)
        if i < len(stats) - 1:
            p.hline(652, 884, y + 60, HAIR, 0.5)

    footer(p, 1, "Rohit Singh Rajput   ·   MIT License")
    p.done()


# ------------------------------------------------------------------ slide 2
CARDS = [
    ("01", "Detect change", "Bundle hash and a route delta.", "added / removed routes"),
    ("02", "Build inventory", "HAR per role, JS harvest, gateway log.", "13 endpoints"),
    ("03", "Classify", "Traffic x bundle x spec, three-way.", "9 active · 1 shadow · 3 zombie"),
    ("04", "Plan", "Ranked tests, a rationale each.", "16 catalogued"),
    ("05", "Execute", "One guard: allowlist, bucket, budget.", "39 requests · 0 denied"),
    ("06", "Verify", "Dual-token replay, negative control.", "8 raw hits -> 7 proven"),
    ("07", "Triage", "Dedupe, additive severity, owner.", "7 findings · 1 dup removed"),
    ("08", "Report and retest", "Ticket, SARIF, capsule replay.", "47 audit entries · chain ok"),
]


def slide_built(pdf: PDF) -> None:
    p = pdf.new_page()
    top_rule(p)
    header(p, "01   /   WHAT IS BUILT", "One loop: deploy to proven finding",
           "An autonomous loop with a deterministic core: it decides what changed, what to test and "
           "when to stop. No model sits in the path that proves a finding.")

    gap, cols = 14.0, 4
    cw = (W - 2 * M - gap * (cols - 1)) / cols
    for i, (num, name, body, out) in enumerate(CARDS):
        row, col = divmod(i, cols)
        x = M + col * (cw + gap)
        top = 176 + row * 116
        p.rect(x, top, cw, 104, stroke=HAIR, lw=0.8)
        p.text(x + 12, top + 20, num, F2, 8, 0.45, tracking=1.0)
        p.text(x + 12, top + 42, name, F2, 11, INK)
        p.para(x + 12, top + 60, cw - 24, body, F1, 8.4, 11.5, 0.34, max_lines=2)
        p.hline(x + 12, x + cw - 12, top + 82, 0.92, 0.5)
        p.text(x + 12, top + 96, out, F3, 7.2, 0.30)

    bar = 428
    p.rect(M, bar, W - 2 * M, 44, fill=0.13)
    p.text(M + 16, bar + 17, "SAFETY LAYER", F2, 7.2, 0.88, tracking=1.4)
    p.text(M + 118, bar + 17,
           "8 / 8 out-of-scope attempts refused  ·  deny beats allow  ·  120-request budget  ·  "
           "kill switch  ·  approval gate  ·  hash-chained audit", F1, 8.2, 0.80)
    p.text(M + 16, bar + 34,
           "Traversal, %2e%2e encoding, userinfo smuggling, wrong method and non-http schemes are "
           "refused before a socket opens. Every request is logged, and the audit head is "
           "published so truncation is detectable.", F1, 7.4, 0.62)

    footer(p, 2)
    p.done()


# ------------------------------------------------------------------ slide 3
FINDINGS = [
    ("F-003", "CRIT", "10.0", "Unauthenticated shadow export, PII + financial"),
    ("F-005", "CRIT", "10.0", "Unauthenticated zombie /api/v1/booking/{id}"),
    ("F-007", "HIGH", "8.7", "Payment step skipped: confirmed with 0.00 paid"),
    ("F-001", "HIGH", "8.3", "Cross-tenant read: agency_b reads AGENCY-A 8842"),
    ("F-006", "HIGH", "8.1", "Double refund on one booking"),
    ("F-008", "HIGH", "7.9", "Fare tampering: 100.00 against a 5000.00 quote"),
    ("F-004", "HIGH", "7.0", "Unauthenticated zombie agency summary"),
]

PLAN = [
    ("W1  ·  26 NOV - 3 DEC", "Real inputs, and the trigger",
     "Live HAR per role, gateway-log and DNS adapters, deploy webhook that runs only what moved.",
     "EXIT   delta run sends max 5 requests, under 5 s"),
    ("W2  ·  4 - 10 DEC", "Close the catalogue gap, 5 to 11",
     "Auth, injection and hygiene tests, each with a silence test; matching bugs planted in target.",
     "EXIT   11 of 16 implemented, 5 classes proven"),
    ("W3  ·  11 - 17 DEC", "Publish the speed number",
     "GitHub Action with SARIF upload, gate on new criticals, deploy-to-finding recorded per run.",
     "EXIT   p50 deploy to finding under 10 min, over 10 runs"),
    ("W4  ·  18 - 24 DEC", "Harden, route, record the demo",
     "Owner routing from the asset register, runbook, kill-switch drill, 90-second demo video.",
     "EXIT   staging run, 0 guard violations, every finding owned"),
]


def slide_proof(pdf: PDF) -> None:
    p = pdf.new_page()
    top_rule(p)
    header(p, "02   /   PROOF AND THE PLAN",
           "Seven findings proven today. Four weeks to the live platform.",
           "Findings are what deterministic verification kept, not what a model guessed. The plan "
           "spends the four weeks on the inputs and the classes that are still thin.")

    left, right = M, 470.0
    p.text(left, 172, "PROVEN ON THE DELIBERATELY VULNERABLE TARGET", F2, 7.2, 0.40, tracking=1.2)
    p.hline(left, right, 181, 0.55, 0.9)
    p.text(left, 197, "ID", F2, 7, 0.50, tracking=0.8)
    p.text(left + 52, 197, "SEV", F2, 7, 0.50, tracking=0.8)
    p.text(left + 106, 197, "CVSS", F2, 7, 0.50, tracking=0.8)
    p.text(left + 152, 197, "FINDING", F2, 7, 0.50, tracking=0.8)

    for i, (fid, sev, cvss, desc) in enumerate(FINDINGS):
        y = 218 + i * 25
        p.text(left, y, fid, F3, 8.4, INK)
        p.text(left + 52, y, sev, F2, 7.6, 0.18 if sev == "CRIT" else 0.42)
        p.text(left + 106, y, cvss, F3, 8.4, 0.30)
        p.text(left + 152, y, desc, F1, 8.4, 0.25)
        p.hline(left, right, y + 9, 0.93, 0.5)

    totals = [("8 raw hits -> 7 findings", "1 duplicate removed by fingerprint"),
              ("39 requests, 0 denied", "p95 1.3 ms · budget 81 of 120 left"),
              ("112 tests, chain intact", "47 audit entries · head published")]
    for i, (a, b) in enumerate(totals):
        y = 412 + i * 14
        p.text(left, y, a, F3, 7.4, 0.22)
        p.text(left + 176, y, b, F1, 7.4, SOFT)

    p.para(left, 466, 400,
           "RUBRIC  30 valid findings · 20 precision · 20 safety · 10 speed · 10 report · "
           "10 discovery", F1, 7.2, 10, 0.50, max_lines=1)

    px = 512.0
    p.vline(px - 26, 168, 470, HAIR, 0.7)
    p.text(px, 172, "FINALISED PLAN  ·  PROTOTYPE ROUND", F2, 7.2, 0.40, tracking=1.2)
    p.hline(px, W - M, 181, 0.55, 0.9)

    for i, (week, title, body, exit_line) in enumerate(PLAN):
        top = 196 + i * 70
        p.text(px, top, week, F3, 7, 0.45)
        p.text(px, top + 14, title, F2, 9.6, INK)
        p.para(px, top + 28, W - M - px, body, F1, 7.6, 10, 0.34, max_lines=2)
        p.text(px, top + 48, exit_line, F3, 7.2, 0.22)
        if i < len(PLAN) - 1:
            p.hline(px, W - M, top + 62, 0.93, 0.5)

    footer(p, 3)
    p.done()


# ------------------------------------------------------------------ slide 4
def slide_thanks(pdf: PDF) -> None:
    p = pdf.new_page()
    top_rule(p)
    p.text(M, 54, "04   /   CLOSING", F2, 8.5, 0.35, tracking=1.6)
    p.hline(M, W - M, 70, HAIR)

    p.text(M, 168, "Thank you.", F2, 46, INK)
    p.text(M, 200, "Three things worth remembering, and one command to check them.", F1, 13, MID)
    p.hline(M, 300, 216, INK, 2.2)

    cols = [
        ("WHAT WE BUILT",
         "A change-triggered DAST loop with a deterministic verifier, and a zombie and shadow "
         "inventory that carries an owner and a recommendation."),
        ("WHY IT WINS",
         "Precision and safety are 40% of the rubric, and both are structural: a negative "
         "control on every test, and an allowlist the scanner cannot reach."),
        ("WHAT IS NEXT",
         "Four weeks to the live platform: real inputs and a deploy trigger, 11 of 16 tests "
         "implemented, and a published deploy-to-finding time."),
    ]
    cw = (W - 2 * M - 2 * 32) / 3
    for i, (head, body) in enumerate(cols):
        x = M + i * (cw + 32)
        p.text(x, 258, head, F2, 7.4, 0.40, tracking=1.3)
        p.hline(x, x + cw, 266, 0.45, 0.9)
        p.para(x, 284, cw, body, F1, 9.2, 13.5, 0.28, max_lines=5)

    p.rect(M, 372, W - 2 * M, 74, fill=0.955)
    lines = [
        "$ git clone https://github.com/Rohit4507/Agentic-DAST.git",
        "$ python3 -m target.app --port 8080        # terminal 1",
        "$ python3 run.py all --approve-writes      # 7 findings, exit 0",
    ]
    for i, line in enumerate(lines):
        p.text(M + 18, 396 + i * 15, line, F3, 8.2, 0.22)
    p.text(W - M - 18, 396, "no pip install", F2, 7.4, 0.45, align="right")
    p.text(W - M - 18, 411, "no API key", F2, 7.4, 0.45, align="right")
    p.text(W - M - 18, 426, "no model call", F2, 7.4, 0.45, align="right")

    p.text(M, 470, "Rohit Singh Rajput  ·  MIT License  ·  2026", F1, 8, SOFT)
    footer(p, 4)
    p.done()


# ------------------------------------------------------------------ checks
def check(pdf: PDF) -> None:
    for page, x, y, w, h, s in pdf.boxes:
        assert x >= 24 and x + w <= W - 20, f"p{page} horizontal overflow: {s[:44]!r} (x={x:.1f}, w={w:.1f})"
        assert y >= -8 and y + h <= H - 12, f"p{page} vertical overflow: {s[:44]!r} (y={y:.1f})"
    for page in range(1, pdf.pages_created + 1):
        boxes = sorted((b for b in pdf.boxes if b[0] == page), key=lambda b: b[2])
        for i, a in enumerate(boxes):
            for b in boxes[i + 1:]:
                if b[2] - a[2] >= 9:
                    break
                if a[1] < b[1] + b[3] - 1 and b[1] < a[1] + a[3] - 1:
                    if a[2] < b[2] + b[4] - 1 and b[2] < a[2] + a[4] - 1:
                        raise AssertionError(f"p{page} overlap: {a[5][:34]!r} / {b[5][:34]!r}")


def main() -> None:
    pdf = PDF()
    slide_cover(pdf)
    slide_built(pdf)
    slide_proof(pdf)
    slide_thanks(pdf)
    check(pdf)
    out = Path(__file__).with_name("VOYAGEHACK4_Agentic_DAST_SUBMISSION.pdf")
    pdf.save(out)
    print(f"wrote {out.name}  ({out.stat().st_size / 1024:.1f} KB, {len(pdf.streams)} pages, "
          f"{len(pdf.boxes)} text runs)")


if __name__ == "__main__":
    main()
