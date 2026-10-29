"""Render the paper's CJK runs as vector PDF snippets for the pdflatex build.

The USENIX template is built with pdflatex, which cannot load an OpenType CJK font, and
the build host has neither xeCJK/xelatex nor CJKutf8. Instead of changing the engine (and
with it the page metrics the 13-page limit is measured with), each CJK run is drawn
from a Noto CJK font's outlines into a one-line PDF of exactly n ems, and the build
includes it where the run occurs. The text is then visible in the PDF as vector glyphs
(not selectable as text).

    python3 cjk_glyphs.py FONT.otf OUTDIR RUN [RUN ...]   -> OUTDIR/cjk<i>.pdf, one per RUN

Font: Noto Serif CJK SC (SIL OFL 1.1), NotoSerifCJKsc-Regular.otf from
https://github.com/notofonts/noto-cjk (Serif/OTF/SimplifiedChinese), about 24 MB. The
build looks for it at $CJK_FONT, then /workspace/.tools/fonts/NotoSerifCJKsc-Regular.otf.
"""
from __future__ import annotations

import pathlib
import sys
import zlib

from fontTools.pens.basePen import BasePen
from fontTools.ttLib import TTFont

ASC, DESC = 880, 120          # glyph box in font units (1000/em): baseline at 12% of height


class PdfPen(BasePen):
    def __init__(self, glyphset, dx: float):
        super().__init__(glyphset)
        self.ops: list[str] = []
        self.dx = dx

    def _p(self, pt):
        return f"{pt[0] + self.dx:.1f} {pt[1] + DESC:.1f}"

    def _moveTo(self, pt):
        self.ops.append(f"{self._p(pt)} m")

    def _lineTo(self, pt):
        self.ops.append(f"{self._p(pt)} l")

    def _curveToOne(self, p1, p2, p3):
        self.ops.append(f"{self._p(p1)} {self._p(p2)} {self._p(p3)} c")

    def _closePath(self):
        self.ops.append("h")


def render(font: TTFont, text: str, out: pathlib.Path) -> None:
    cmap = font.getBestCmap()
    gs = font.getGlyphSet()
    upem = font["head"].unitsPerEm
    ops, x = [], 0.0
    for ch in text:
        name = cmap.get(ord(ch))
        if name is None:
            raise SystemExit(f"glyph for {ch!r} not in font")
        pen = PdfPen(gs, x * 1000 / upem)
        gs[name].draw(pen)
        ops += pen.ops
        x += upem                                  # ideographs are one em wide
    width = len(text) * 1000
    # content in font units, scaled to 10 bp per em; MediaBox is n ems by 1 em
    stream = ("q 0.01 0 0 0.01 0 0 cm 0 g\n" + "\n".join(ops) + "\nf\nQ\n").encode()
    data = zlib.compress(stream)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width / 100:.2f} {(ASC + DESC) / 100:.2f}] "
        f"/Contents 4 0 R /Resources << >> >>".encode(),
        f"<< /Length {len(data)} /Filter /FlateDecode >>\nstream\n".encode() + data + b"\nendstream",
    ]
    pdf, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offs.append(len(pdf))
        pdf += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(pdf)
    pdf += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    pdf += b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    pdf += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    out.write_bytes(bytes(pdf))


def main(argv: list[str]) -> int:
    font = TTFont(argv[1], lazy=True)
    outdir = pathlib.Path(argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    for i, run in enumerate(argv[3:]):
        render(font, run, outdir / f"cjk{i}.pdf")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
