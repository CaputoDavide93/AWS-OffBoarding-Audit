"""Every diagram in this repository is a drawn SVG, and has to stay one.

`tools/gen_diagram.py` draws each diagram twice, one file per colour scheme,
served from a `<picture>` element. These tests are the obligations that come
with that: the pictures are what the generator draws, they reference files that
exist, they carry nothing GitHub strips, and Mermaid does not quietly come back
carrying an HTML entity that GitHub decodes before Mermaid parses it.
"""
import html
import importlib
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
PAGES = sorted(ROOT.glob("*.md")) + sorted(ROOT.glob("docs/**/*.md"))
MERMAID = re.compile(r"^```mermaid[^\n]*\n(.*?)^```", re.S | re.M)
ENTITY = re.compile(r"&(?:[A-Za-z][A-Za-z0-9]{1,31}|#\d{1,7}|#[Xx][0-9A-Fa-f]{1,6});")


def _generator():
    sys.path.insert(0, str(ROOT / "tools"))
    return importlib.reload(importlib.import_module("gen_diagram"))


class DiagramTests(unittest.TestCase):
    def test_every_committed_svg_is_what_the_generator_draws(self):
        """A hand-edited SVG is a lie waiting to happen."""
        module = _generator()
        stale = []
        for name, fn in module.DIAGRAMS.items():
            for scheme in module.SCHEMES:
                path = ASSETS / f"{name}-{scheme}.svg"
                if not path.exists():
                    stale.append(f"{path.name} is missing")
                elif path.read_text(encoding="utf-8") != fn(scheme):
                    stale.append(f"{path.name} differs from tools/gen_diagram.py")
        self.assertFalse(stale, "re-run tools/gen_diagram.py rather than editing SVGs:\n  "
                         + "\n  ".join(stale))

    def test_every_picture_points_at_files_that_exist(self):
        """A `<picture>` with a wrong path shows the alt text and nothing else."""
        missing = []
        for page in PAGES:
            for ref in re.findall(r'(?:srcset|src)="([^"]+\.svg)"', page.read_text(encoding="utf-8")):
                if not (page.parent / ref).exists():
                    missing.append(f"{page.relative_to(ROOT)} -> {ref}")
        self.assertFalse(missing, "a diagram reference does not resolve:\n  " + "\n  ".join(missing))

    def test_every_diagram_offers_both_schemes_and_alt_text(self):
        """One scheme is half a diagram, and no alt text is none of one."""
        problems = []
        for page in PAGES:
            where = page.relative_to(ROOT)
            for block in re.findall(r"<picture>.*?</picture>", page.read_text(encoding="utf-8"), re.S):
                if "prefers-color-scheme: dark" not in block:
                    problems.append(f"{where}: a <picture> with no dark source")
                if not re.search(r'alt="[^"]{40,}"', block):
                    problems.append(f"{where}: a <picture> with missing or thin alt text")
        self.assertFalse(problems, "\n  " + "\n  ".join(problems))

    def test_the_svgs_carry_nothing_github_will_strip(self):
        """GitHub sanitises SVG in markdown, silently."""
        bad = []
        for path in sorted(ASSETS.glob("*.svg")):
            svg = path.read_text(encoding="utf-8")
            for banned in ("<script", "<style", "@import", "<foreignObject"):
                if banned in svg:
                    bad.append(f"{path.name} contains {banned}")
        self.assertFalse(bad, "GitHub strips these without saying so:\n  " + "\n  ".join(bad))

    def test_mermaid_has_not_come_back_unguarded(self):
        """Any Mermaid block that returns must not carry an HTML entity or odd quotes."""
        bad = []
        for page in PAGES:
            text = page.read_text(encoding="utf-8")
            for match in MERMAID.finditer(text):
                line = text[: match.start()].count("\n") + 2
                for offset, row in enumerate(match.group(1).splitlines()):
                    found = ENTITY.search(row)
                    if found:
                        bad.append(f"{page.relative_to(ROOT)}:{line + offset}: {found.group(0)}")
                for offset, row in enumerate(html.unescape(match.group(1)).splitlines()):
                    if row.count('"') % 2:
                        bad.append(f"{page.relative_to(ROOT)}:{line + offset}: odd quotes once decoded")
        self.assertFalse(bad, "\n  " + "\n  ".join(bad))

    def test_there_are_diagrams_to_check(self):
        """A regex that silently matches nothing is not a test."""
        module = _generator()
        self.assertGreaterEqual(len(module.DIAGRAMS), 1)
        pictures = sum(len(re.findall(r"<picture>", p.read_text(encoding="utf-8"))) for p in PAGES)
        self.assertGreaterEqual(pictures, len(module.DIAGRAMS))


if __name__ == "__main__":
    unittest.main()
