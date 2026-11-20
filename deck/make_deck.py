#!/usr/bin/env python3
"""Generate the submission deck as a designed, monochrome PDF - standard library only.

    python3 deck/make_deck.py
    -> deck/VOYAGEHACK4_Agentic_DAST_SUBMISSION.pdf

Design system
    grid      12 columns, 56 pt margin, 16 pt gutter
    palette   grayscale only: 0.07 ink, 0.45 mid, 0.62 soft, 0.86 hair
    type      Helvetica / Courier (base-14, no embedding, opens anywhere)
    rhythm    dark cover, two light content pages, dark close

Every figure printed is one the pipeline actually produced; see
deck/IMPLEMENTATION_PLAN.md for the run that measured it.
"""

from __future__ import annotations

import zlib
from pathlib import Path

W, H = 960.0, 540.0
M = 56.0
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
        for i, base in enumerate((b"Helvetica", b"Helvetica-Bold", b"Courier", b"Courier-Bold")):
            objs[3 + i] = (b"<</Type /Font /Subtype /Type1 /BaseFont /" + base +
                           b" /Encoding /WinAnsiEncoding>>")
        resources = b"<</Font <</F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R>>>>"
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

    def hline(self, x1: float, x2: float, top: float, gray: float = 0.86, lw: float = 0.6) -> None:
        self.ops.append(f"{lw:.2f} w {gray:.3f} G {x1:.2f} {H - top:.2f} m {x2:.2f} {H - top:.2f} l S")

    def vline(self, x: float, top1: float, top2: float, gray: float = 0.86, lw: float = 0.6) -> None:
        self.ops.append(f"{lw:.2f} w {gray:.3f} G {x:.2f} {H - top1:.2f} m {x:.2f} {H - top2:.2f} l S")

    def rect(self, x: float, top: float, w: float, h: float, fill: float | None = None,
             stroke: float | None = None, lw: float = 0.6) -> None:
        y = H - top - h
        if fill is not None:
            self.ops.append(f"{fill:.3f} g {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")
        if stroke is not None:
            self.ops.append(f"{lw:.2f} w {stroke:.3f} G {x:.2f} {y:.2f} {w:.2f} {h:.2f} re S")

    def done(self) -> None:
        self.pdf.streams.append(zlib.compress("\n".join(self.ops).encode("latin-1"), 9))


INK, MID, SOFT, HAIR = 0.09, 0.42, 0.60, 0.87
DARK_PAGE, DARK_PANEL, DARK_LINE = 0.075, 0.145, 0.30


def meta_row(p: Page, left: str, right: str, gray: float, rule: float) -> None:
    p.text(M, 50, left, F2, 8, gray, tracking=1.6)
    p.text(W - M, 50, right, F1, 8, gray, tracking=1.4, align="right")
    p.hline(M, W - M, 64, rule)


def light_header(p: Page, kicker: str, title: str, sub: str) -> None:
    p.rect(0, 0, W, 4.5, fill=INK)
    meta_row(p, kicker, "TBO.COM   ·   VOYAGEHACK 4.0", 0.40, HAIR)
    p.text(M, 112, title, F2, 26, INK)
    p.para(M, 138, W - 2 * M, sub, F1, 10.5, 15, MID, max_lines=2)


def footer(p: Page, n: int, dark: bool = False) -> None:
    gray, rule = (0.52, 0.26) if dark else (SOFT, HAIR)
    p.hline(M, W - M, 496, rule, 0.6)
    p.text(M, 516, "Rohit Singh Rajput   ·   MIT License   ·   2026", F1, 8, gray)
    p.text(W - M, 516, f"github.com/Rohit4507/Agentic-DAST      {n} / 4",
           F3, 7.5, gray, align="right")


# ------------------------------------------------------------------ slide 1
def slide_cover(pdf: PDF) -> None:
    p = pdf.new_page()
    p.rect(0, 0, W, H, fill=DARK_PAGE)

    meta_row(p, "TBO.COM   /   VOYAGEHACK 4.0", "SECURITY HACKATHON 2026", 0.58, DARK_LINE)

    p.text(M, 182, "Agentic", F2, 54, 0.97)
    p.text(M, 240, "Real-Time DAST", F2, 54, 0.97)
    p.text(M, 276, "Security agents that hunt vulnerabilities as the platform changes.",
           F1, 13, 0.64)
    p.hline(M, W - M, 302, 0.22, 0.8)

    p.text(M, 328, "$  python3 run.py all --approve-writes", F4, 9, 0.78)
    p.text(M + 300, 328, "->  exit 0 in 3.89 s", F3, 8.5, 0.45)

    stats = [
        ("7", "VERIFIED FINDINGS", "2 critical, 5 high"),
        ("13", "ENDPOINTS MAPPED", "9 active, 1 shadow, 3 zombie"),
        ("39", "REQUESTS AUDITED", "0 denied, 81 of 120 left"),
        ("228", "TESTS PASSING", "standard library only"),
    ]
    for i, (num, label, note) in enumerate(stats):
        x = M + i * 214
        p.text(x, 372, label, F2, 7.5, 0.50, tracking=1.4)
        p.text(x, 458, num, F2, 74, 0.95)
        p.text(x, 480, note, F1, 8, 0.46)
        if i:
            p.vline(x - 22, 360, 486, 0.24, 0.6)

    footer(p, 1, dark=True)
    p.done()


# ------------------------------------------------------------------ slide 2
STAGES = [
    ("01", "Detect change", "route delta"),
    ("02", "Inventory", "13 endpoints"),
    ("03", "Classify", "9 / 1 / 3"),
    ("04", "Plan", "16 catalogued"),
    ("05", "Execute", "39 requests"),
    ("06", "Verify", "7 proven"),
    ("07", "Triage", "8 hits -> 7"),
    ("08", "Report + retest", "47 entries"),
]


def slide_loop(pdf: PDF) -> None:
    p = pdf.new_page()
    light_header(p, "01   /   WHAT IS BUILT", "One loop, deploy to proven finding",
                 "An autonomous loop with a deterministic core: it decides what changed, what to "
                 "test and when to stop. No model sits in the path that proves a finding.")

    p.text(M, 180, "THE LOOP", F2, 7.2, 0.45, tracking=1.5)
    p.hline(M, 820, 206, 0.55, 0.8)

    col = 106.0
    for i, (num, name, out) in enumerate(STAGES):
        x = M + i * col
        cx = x + 8
        p.rect(cx - 4.5, 201.5, 9, 9, fill=INK)
        p.text(x, 194, num, F3, 7, 0.40)
        p.text(x, 232, name, F2, 9.5, INK)
        p.text(x, 248, out, F3, 7, 0.36)

    # two panels
    p.text(M, 300, "WHAT IT EMITS", F2, 7.2, 0.45, tracking=1.5)
    p.hline(M, 470, 308, HAIR, 0.6)
    items = [
        ("work/inventory.json", "13 endpoints, classified"),
        ("work/findings/F-*/capsule.json", "replayable proof"),
        ("work/report.sarif", "CI-ready, 7 results"),
        ("work/REPORT.md", "7 tickets, 7 owners"),
    ]
    for i, (art, desc) in enumerate(items):
        y = 328 + i * 16
        p.text(M, y, art, F3, 7.4, 0.28)
        p.text(M + 196, y, desc, F1, 7.4, SOFT)

    p.text(512, 300, "SAFETY, IN ONE CHOKEPOINT", F2, 7.2, 0.45, tracking=1.5)
    p.hline(512, W - M, 308, HAIR, 0.6)
    guards = [
        "8 / 8 out-of-scope attempts refused",
        "120-request budget, 8 rps per host",
        "kill switch and human approval gate",
        "hash-chained audit, head published",
    ]
    for i, line in enumerate(guards):
        p.text(512, 328 + i * 16, line, F1, 8.4, 0.30)

    bar = 416
    p.rect(M, bar, W - 2 * M, 56, fill=0.10)
    p.text(M + 18, bar + 24, "RULES OF ENGAGEMENT", F2, 7.2, 0.72, tracking=1.5)
    p.text(M + 18, bar + 42,
           "Every request logged   ·   provided accounts only   ·   no destructive tests   ·   "
           "minimum evidence, no bulk extraction", F1, 8.4, 0.66)

    footer(p, 2)
    p.done()


# ------------------------------------------------------------------ slide 3
FINDINGS = [
    ("F-003", "CRIT", 10.0, "Unauthenticated shadow export, PII"),
    ("F-005", "CRIT", 10.0, "Unauthenticated zombie /api/v1"),
    ("F-007", "HIGH", 8.7, "Payment step skipped"),
    ("F-001", "HIGH", 8.3, "Cross-tenant booking read"),
    ("F-006", "HIGH", 8.1, "Double refund"),
    ("F-008", "HIGH", 7.9, "Fare tampering"),
    ("F-004", "HIGH", 7.0, "Unauthenticated zombie summary"),
]

PLAN = [
    ("W1  26 NOV - 3 DEC", "Real inputs and the trigger",
     "Live HAR per role, gateway and DNS adapters, deploy webhook.",
     "delta run: 17 requests, 1.1 s today"),
    ("W2  4 - 10 DEC", "Catalogue 5 to 11",
     "Auth, injection and hygiene tests, each with a silence test.",
     "5 of 16 today, 11 by 10 Dec"),
    ("W3  11 - 17 DEC", "Publish the speed number",
     "GitHub Action, SARIF upload, deploy-to-finding per run.",
     "p50 under 10 min over 10 runs"),
    ("W4  18 - 24 DEC", "Harden, route, record",
     "Owner routing, runbook, kill-switch drill, demo video.",
     "0 guard violations on staging"),
]


def slide_proof(pdf: PDF) -> None:
    p = pdf.new_page()
    light_header(p, "02   /   PROOF AND THE PLAN",
                 "Seven findings proven today. Four weeks to the live platform.",
                 "Findings are what deterministic verification kept, not what a model guessed. "
                 "The plan spends the four weeks on the inputs and the classes still thin.")

    # ---- severity chart
    p.text(M, 186, "PROVEN FINDINGS  ·  CVSS IN BUSINESS CONTEXT", F2, 7.2, 0.45, tracking=1.2)
    p.hline(M, 470, 194, HAIR, 0.6)
    x_id, x_label, x_bar, bar_max = M, M + 46, 300.0, 110.0
    for frac in (0.5, 1.0):   # faint value grid, drawn under the bars
        gx = x_bar + frac * bar_max
        p.vline(gx, 206, 216 + len(FINDINGS) * 26 - 10, 0.93, 0.5)
    p.vline(x_bar, 206, 216 + len(FINDINGS) * 26 - 10, 0.93, 0.5)
    for i, (fid, sev, score, label) in enumerate(FINDINGS):
        y = 216 + i * 26
        p.text(x_id, y, fid, F3, 8, 0.22)
        p.text(x_label, y, label, F1, 8.2, 0.30)
        p.text(x_bar - 10, y, f"{score:.1f}", F3, 7.6, 0.40, align="right")
        p.rect(x_bar, y - 6, score / 10 * bar_max, 9, fill=0.09 if sev == "CRIT" else 0.48)

    axis = 216 + len(FINDINGS) * 26 - 10
    p.hline(x_bar, x_bar + bar_max, axis, 0.50, 0.8)
    for frac, lab in ((0.0, "0"), (0.5, "5"), (1.0, "10")):
        tx = x_bar + frac * bar_max
        p.hline(tx, tx, axis, 0.50, 0.8)
        p.rect(tx, axis, 0.5, 4, fill=0.50)
        p.text(tx, axis + 12, lab, F3, 6.8, 0.45, align="center")

    legend = axis + 34
    p.rect(M, legend - 5, 7, 7, fill=0.09)
    p.text(M + 12, legend, "CRITICAL   2", F2, 7, 0.35, tracking=0.8)
    p.rect(M + 108, legend - 5, 7, 7, fill=0.48)
    p.text(M + 120, legend, "HIGH   5", F2, 7, 0.35, tracking=0.8)
    p.text(M + 196, legend, "8 raw hits -> 7 findings  ·  1 duplicate removed",
           F3, 7.2, 0.30)
    p.text(M, legend + 22, "every finding ships a replayable capsule; retest closes it on fix",
           F1, 7.6, SOFT)

    # ---- timeline
    p.text(512, 186, "FINALISED PLAN  ·  26 NOV TO 24 DEC", F2, 7.2, 0.45, tracking=1.2)
    p.hline(512, W - M, 194, HAIR, 0.6)
    p.vline(516, 208, 452, 0.55, 0.8)
    for i, (week, title, body, exit_line) in enumerate(PLAN):
        top = 216 + i * 62
        p.rect(512.5, top - 6, 7, 7, fill=INK)
        p.text(534, top, week, F3, 7, 0.45)
        p.text(534, top + 14, title, F2, 9.6, INK)
        p.para(534, top + 27, W - M - 534, body, F1, 7.5, 9.6, 0.36, max_lines=2)
        p.text(534, top + 47, exit_line, F3, 6.9, 0.24)

    p.text(M, 470, "RUBRIC   30 valid findings  ·  20 precision  ·  20 safety  ·  10 speed  ·  "
                   "10 report  ·  10 discovery", F1, 7.2, 0.50)

    footer(p, 3)
    p.done()


# ------------------------------------------------------------------ slide 4
def slide_close(pdf: PDF) -> None:
    p = pdf.new_page()
    p.rect(0, 0, W, H, fill=DARK_PAGE)

    p.text(M, 54, "THANK YOU", F2, 8, 0.55, tracking=1.6)
    p.hline(M, W - M, 68, DARK_LINE)

    p.text(M, 166, "Thank you.", F2, 46, 0.97)
    p.text(M, 196, "Three things worth remembering, and one command to check them.", F1, 12, 0.60)
    p.hline(M, W - M, 214, 0.22, 0.8)

    cols = [
        ("WHAT WE BUILT",
         "A change-triggered DAST loop with a deterministic verifier, and a zombie and shadow "
         "inventory that carries an owner and a recommendation."),
        ("WHY IT WINS",
         "Precision and safety are 40% of the rubric, and both are structural: a negative "
         "control on every route-driven test, and an allowlist the scanner cannot reach."),
        ("WHAT IS NEXT",
         "Four weeks to the live platform: real inputs and a deploy trigger, 5 of 16 tests "
         "implemented today (11 by 24 Dec), and a published deploy-to-finding time."),
    ]
    cw = 248.0
    for i, (head, body) in enumerate(cols):
        x = M + i * 288
        p.text(x, 248, head, F2, 7.4, 0.52, tracking=1.3)
        p.hline(x, x + cw, 256, 0.34)
        p.para(x, 274, cw, body, F1, 9, 13.5, 0.82, max_lines=5)

    p.rect(M, 374, W - 2 * M, 82, fill=DARK_PANEL, stroke=0.26)
    lines = [
        "$ git clone https://github.com/Rohit4507/Agentic-DAST.git",
        "$ python3 -m target.app --port 8080        # terminal 1",
        "$ python3 run.py all --approve-writes      # 7 findings, exit 0",
    ]
    for i, line in enumerate(lines):
        p.text(M + 20, 398 + i * 16, line, F3, 8.2, 0.88)
    p.text(W - M - 20, 398, "no pip install", F2, 7.4, 0.55, align="right")
    p.text(W - M - 20, 414, "no API key", F2, 7.4, 0.55, align="right")
    p.text(W - M - 20, 430, "no model call", F2, 7.4, 0.55, align="right")

    footer(p, 4, dark=True)
    p.done()


# ------------------------------------------------------------------ checks
def check(pdf: PDF) -> None:
    for page, x, y, w, h, s in pdf.boxes:
        assert x >= 24 and x + w <= W - 18, \
            f"p{page} horizontal overflow: {s[:44]!r} (x={x:.1f}, right={x + w:.1f})"
        assert y >= -10 and y + h <= H - 10, f"p{page} vertical overflow: {s[:44]!r} (y={y:.1f})"
    for page in range(1, pdf.pages_created + 1):
        boxes = sorted((b for b in pdf.boxes if b[0] == page), key=lambda b: b[2])
        for i, a in enumerate(boxes):
            for b in boxes[i + 1:]:
                if b[2] - a[2] >= 8:
                    break
                if a[1] < b[1] + b[3] - 1 and b[1] < a[1] + a[3] - 1:
                    if a[2] < b[2] + b[4] - 1 and b[2] < a[2] + a[4] - 1:
                        raise AssertionError(f"p{page} overlap: {a[5][:36]!r} / {b[5][:36]!r}")


def main() -> None:
    pdf = PDF()
    slide_cover(pdf)
    slide_loop(pdf)
    slide_proof(pdf)
    slide_close(pdf)
    check(pdf)
    out = Path(__file__).with_name("VOYAGEHACK4_Agentic_DAST_SUBMISSION.pdf")
    pdf.save(out)
    print(f"wrote {out.name}  ({out.stat().st_size / 1024:.1f} KB, {len(pdf.streams)} pages, "
          f"{len(pdf.boxes)} text runs)")


if __name__ == "__main__":
    main()
