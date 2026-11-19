#!/usr/bin/env python3
"""Render a wireframe PNG of the submission deck.

Not a PDF renderer: it redraws the rectangles, rules and text extents that the
generator emitted, so composition, spacing and collisions can be reviewed
without a PDF viewer. Standard library only.
"""
from __future__ import annotations

import re
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from make_deck import advance  # noqa: E402

SCALE = 2
SRC = Path(__file__).with_name("VOYAGEHACK4_Agentic_DAST_SUBMISSION.pdf")


def png(path: Path, w: int, h: int, rgb: bytearray) -> None:
    raw = bytearray()
    stride = w * 3
    for y in range(h):
        raw.append(0)
        raw += rgb[y * stride:(y + 1) * stride]

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    path.write_bytes(b"\x89PNG\r\n\x1a\n"
                     + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
                     + chunk(b"IEND", b""))


class Canvas:
    def __init__(self, w: int, h: int) -> None:
        self.w, self.h = w, h
        self.buf = bytearray([255] * (w * h * 3))

    def px(self, x: int, y: int, g: float) -> None:
        if 0 <= x < self.w and 0 <= y < self.h:
            v = max(0, min(255, int(round(255 * g))))
            i = (y * self.w + x) * 3
            self.buf[i] = self.buf[i + 1] = self.buf[i + 2] = v

    def rect(self, x: float, y: float, w: float, h: float, g: float) -> None:
        for yy in range(int(round(y * SCALE)), int(round((y + max(h, 0.5)) * SCALE))):
            for xx in range(int(round(x * SCALE)), int(round((x + max(w, 0.5)) * SCALE))):
                self.px(xx, yy, g)

    def outline(self, x: float, y: float, w: float, h: float, g: float) -> None:
        self.rect(x, y, w, 0.5, g)
        self.rect(x, y + h, w, 0.5, g)
        self.rect(x, y, 0.5, h, g)
        self.rect(x + w, y, 0.5, h, g)

    def glyphs(self, x: float, baseline: float, s: str, font: str, size: float, g: float) -> None:
        cx = x
        for ch in s:
            w = advance(font, size, ch)
            if ch != " " and w > 0:
                self.rect(cx + w * 0.14, baseline - size * 0.70,
                          max(0.5, w * 0.60), size * 0.70, g)
            cx += w


RE_FILL = re.compile(r"([\d.]+) g ([\d.-]+) ([\d.-]+) ([\d.]+) ([\d.]+) re f")
RE_STROKE = re.compile(r"[\d.]+ w ([\d.]+) G ([\d.-]+) ([\d.-]+) ([\d.]+) ([\d.]+) re S")
RE_LINE = re.compile(r"[\d.]+ w ([\d.]+) G ([\d.-]+) ([\d.-]+) m ([\d.-]+) ([\d.-]+) l S")
RE_TEXT = re.compile(r"BT /(\w+) ([\d.]+) Tf(?: [\d.-]+ Tc)? 1 0 0 1 ([\d.-]+) ([\d.-]+) Tm \((.*)\) Tj ET")
RE_GRAY = re.compile(r"([\d.]+) g")


def render(page_stream: bytes, canvas: Canvas) -> None:
    gray = 0.0
    for raw in page_stream.decode("latin-1").split("\n"):
        cmd = raw.strip()
        if not cmd:
            continue
        m = RE_FILL.fullmatch(cmd)
        if m:
            x, y, w, h = (float(m.group(i)) for i in range(2, 6))
            canvas.rect(x, 540 - y - h, w, h, float(m.group(1)))
            continue
        m = RE_STROKE.fullmatch(cmd)
        if m:
            x, y, w, h = (float(m.group(i)) for i in range(2, 6))
            canvas.outline(x, 540 - y - h, w, h, float(m.group(1)))
            continue
        m = RE_LINE.fullmatch(cmd)
        if m:
            x1, y1, x2, y2 = (float(m.group(i)) for i in range(2, 6))
            if abs(y1 - y2) < 0.01:
                canvas.rect(min(x1, x2), 540 - y1, abs(x2 - x1), 0.35, float(m.group(1)))
            else:
                canvas.rect(x1, 540 - max(y1, y2), 0.35, abs(y2 - y1), float(m.group(1)))
            continue
        m = RE_TEXT.fullmatch(cmd)
        if m:
            canvas.glyphs(float(m.group(3)), 540 - float(m.group(4)), m.group(5),
                          m.group(1), float(m.group(2)), gray)
            continue
        m = RE_GRAY.fullmatch(cmd)
        if m:
            gray = float(m.group(1))


def main() -> None:
    data = SRC.read_bytes()
    streams = []
    for m in re.finditer(rb"stream\n(.*?)\nendstream", data, re.S):
        try:
            streams.append(zlib.decompress(m.group(1)))
        except Exception:
            pass
    for i, page in enumerate(streams[-4:], 1):
        canvas = Canvas(960 * SCALE, 540 * SCALE)
        render(page, canvas)
        out = Path(f"/tmp/deck_page{i}.png")
        png(out, canvas.w, canvas.h, canvas.buf)
        print("wrote", out)


if __name__ == "__main__":
    main()
