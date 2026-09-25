#!/usr/bin/env python3
"""Draw this repository's diagrams as SVG, one file per colour scheme.

  docs/assets/<name>-light.svg
  docs/assets/<name>-dark.svg

Drawn rather than written in Mermaid, because GitHub renders Mermaid on its
own terms: it picks the theme, pins the version, ignores styling, and decodes
HTML entities before parsing. Drawn here, there is one rule instead: **GitHub
sanitises SVG in markdown**, so no <style>, no <script>, no web font and no
<foreignObject>. Every colour is a presentation attribute and the type is a
system stack. Each pair is served from one <picture>, which GitHub switches on
prefers-color-scheme.

Layout is explicit rather than solved. The diagrams are small enough that
placing them by hand is cheaper than a layout engine nobody can predict.

House rules: a slate scale, a single accent on the one component that matters
in each picture, drawn icons rather than emoji, monospace for anything that is
literally typed, and text contrast at or above 4.5:1 in both schemes.

Standard library only. After changing a diagram, run:

  python3 tools/gen_diagram.py
"""
from __future__ import annotations

import pathlib
from xml.sax.saxutils import escape

ROOT = pathlib.Path(__file__).resolve().parents[1]
SANS = "system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace"

SCHEMES = {
    "light": dict(card="#ffffff", border="#d8dee4", title="#0f172a", sub="#5b6673",
                  accent="#2b59c3", on_accent="#ffffff", soft="#f1f4f9",
                  line="#94a3b8", rule="#e6e9ee", chip="#475569",
                  warn="#9a3412", warn_soft="#fff4ed", group="#f7f9fb"),
    "dark":  dict(card="#161b22", border="#30363d", title="#e6edf3", sub="#9aa4b0",
                  accent="#4c7ef3", on_accent="#ffffff", soft="#1b2230",
                  line="#6b7684", rule="#232a33", chip="#aeb7c2",
                  warn="#ffa657", warn_soft="#2a1d14", group="#11151b"),
}

# Stroked glyphs on a 24x24 grid, drawn rather than typed.
ICONS = {
    "chip":     "M8 8h8v8H8z M5 5h14v14H5z M10 2v3 M14 2v3 M10 19v3 M14 19v3 M2 10h3 M2 14h3 M19 10h3 M19 14h3",
    "cloud":    "M7 18h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.3 9.2 4.4 4.4 0 0 0 7 18z",
    "database": "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6 "
                "M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
    "document": "M6 3h8l4 4v14H6z M14 3v4h4 M9 12h6 M9 16h6",
    "chart":    "M4 4v16h16 M8 16v-4 M12 16V8 M16 16v-6",
    "shield":   "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z M8.5 12l2.5 2.5 4.5-4.5",
    "users":    "M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z M2.5 20c.6-3.5 3.3-6 6.5-6s5.9 2.5 6.5 6 "
                "M16 4.5a3.5 3.5 0 0 1 0 6.5 M18 14c2 .7 3.3 2.8 3.5 6",
    "chat":     "M4 5h16v11H9l-5 4z M8 9.5h8 M8 12.5h5",
}


class Canvas:
    """Parts plus a size. No layout engine, on purpose."""

    def __init__(self, w: int, h: int, scheme: str, label: str) -> None:
        self.w, self.h, self.c, self.label = w, h, SCHEMES[scheme], label
        self.parts: list[str] = []

    def add(self, *svg: str) -> "Canvas":
        self.parts.extend(svg)
        return self

    # ── primitives ────────────────────────────────────────────────────────
    def icon(self, name, x, y, colour, size=21):
        s = size / 24
        return (f'<g transform="translate({x:.1f},{y:.1f}) scale({s:.4f})" fill="none" '
                f'stroke="{colour}" stroke-width="1.7" stroke-linecap="round" '
                f'stroke-linejoin="round"><path d="{ICONS[name]}"/></g>')

    def text(self, x, y, s, *, size=13, colour=None, font=None, weight=None,
             anchor="start", opacity=None):
        c = colour or self.c["sub"]
        extra = (f' font-weight="{weight}"' if weight else "") + \
                (f' opacity="{opacity}"' if opacity else "")
        return (f'<text x="{x:.1f}" y="{y:.1f}" font-family="{font or SANS}" '
                f'font-size="{size}" fill="{c}" text-anchor="{anchor}"{extra}>'
                f'{escape(s)}</text>')

    def box(self, x, y, w, h, title, subs=(), *, icon=None, tone="plain", rx=10):
        c = self.c
        fill, edge, tt = c["card"], c["border"], c["title"]
        st, op = c["sub"], ""
        if tone == "accent":
            fill = edge = c["accent"]; tt = st = c["on_accent"]; op = "0.85"
        elif tone == "soft":
            fill = c["soft"]
        elif tone == "warn":
            fill, edge, tt, st = c["warn_soft"], c["warn"], c["warn"], c["warn"]
        out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
               f'stroke="{edge}" stroke-width="1"/>']
        tx = x + 16
        ty = y + (28 if subs else h / 2 + 5)
        if icon:
            out.append(self.icon(icon, x + 16, y + (13 if subs else h / 2 - 10), tt))
            tx = x + 47
        out.append(self.text(tx, ty, title, size=15 if subs else 14,
                             colour=tt, weight="600"))
        for i, s in enumerate(subs):
            out.append(self.text(x + 16, y + 52 + i * 18, s, size=12.5,
                                 colour=st, opacity=op or None))
        return "".join(out)

    def diamond(self, cx, cy, w, h, lines):
        c = self.c
        pts = f"{cx},{cy - h/2} {cx + w/2},{cy} {cx},{cy + h/2} {cx - w/2},{cy}"
        out = [f'<polygon points="{pts}" fill="{c["soft"]}" stroke="{c["border"]}" '
               f'stroke-width="1"/>']
        n = len(lines)
        for i, s in enumerate(lines):
            out.append(self.text(cx, cy - (n - 1) * 7 + i * 14 + 4, s, size=12,
                                 colour=c["title"], anchor="middle"))
        return "".join(out)

    def pill(self, cx, cy, text, *, tone="plain", pad=16, size=13):
        c = self.c
        w = len(text) * size * 0.58 + pad * 2
        h = 32
        fill, edge, col = c["card"], c["border"], c["title"]
        if tone == "accent":
            fill = edge = c["accent"]; col = c["on_accent"]
        elif tone == "soft":
            fill = c["soft"]
        return (f'<rect x="{cx - w/2:.1f}" y="{cy - h/2}" width="{w:.1f}" height="{h}" '
                f'rx="{h/2}" fill="{fill}" stroke="{edge}" stroke-width="1"/>'
                + self.text(cx, cy + 4.5, text, size=size, colour=col, anchor="middle",
                            weight="500")), w

    def edge(self, pts, *, label=None, dash=False, both=False, label_at=0.5,
             label_dy=-9, label_anchor="middle", mono=True):
        c = self.c
        d = ' stroke-dasharray="5 4"' if dash else ""
        path = " ".join(f"{x},{y}" for x, y in pts)
        out = [f'<polyline points="{path}" fill="none" stroke="{c["line"]}" '
               f'stroke-width="1.5"{d} marker-end="url(#a)"'
               + (' marker-start="url(#a)"' if both else "") + "/>"]
        if label:
            (x1, y1), (x2, y2) = pts[0], pts[-1]
            lx = x1 + (x2 - x1) * label_at
            ly = y1 + (y2 - y1) * label_at
            out.append(self.text(lx, ly + label_dy, label, size=11.5,
                                 colour=c["chip"], font=MONO if mono else SANS,
                                 anchor=label_anchor))
        return "".join(out)

    def group(self, x, y, w, h, title):
        c = self.c
        return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" '
                f'fill="{c["group"]}" stroke="{c["border"]}" stroke-width="1" '
                f'stroke-dasharray="6 5"/>'
                + self.text(x + 18, y + 24, title, size=12, colour=c["sub"],
                            weight="600"))

    def footer(self, note):
        return (f'<line x1="24" y1="{self.h - 52}" x2="{self.w - 24}" y2="{self.h - 52}" '
                f'stroke="{self.c["rule"]}" stroke-width="1"/>'
                + self.text(24, self.h - 26, note, size=12.5, colour=self.c["sub"]))

    def render(self) -> str:
        c = self.c
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
            f'width="{self.w}" height="{self.h}" role="img" aria-label="{escape(self.label)}">'
            f'<defs>'
            f'<marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
            f'markerHeight="6" orient="auto-start-reverse">'
            f'<path d="M0 0 10 5 0 10z" fill="{c["line"]}"/></marker>'
            f'</defs>' + "".join(self.parts) + "</svg>"
        )


def card(k, x, y, w, h, title, subs=(), *, mono=(), icon=None, tone="plain"):
    """A Canvas box whose sub-lines at the indices in `mono` are set in monospace.

    Canvas.box sets every sub-line in the sans stack. Paths, commands and flags
    are literally typed, so they are swapped for the monospace stack here,
    in place, with the box's own position and colour.
    """
    svg = k.box(x, y, w, h, title, subs, icon=icon, tone=tone)
    colour = {"accent": k.c["on_accent"], "warn": k.c["warn"]}.get(tone, k.c["sub"])
    opacity = "0.85" if tone == "accent" else None
    for i in mono:
        at = dict(size=12.5, colour=colour, opacity=opacity)
        sans = k.text(x + 16, y + 52 + i * 18, subs[i], **at)
        assert sans in svg, f"sub-line {i} of {title!r} not found"
        svg = svg.replace(sans, k.text(x + 16, y + 52 + i * 18, subs[i], font=MONO,
                                       **dict(at, size=12)), 1)
    return svg


def note(k, x, y, s, *, mono=True, anchor="start"):
    """An edge label placed by hand, for vertical and diagonal edges."""
    return k.text(x, y, s, size=11.5, font=MONO if mono else SANS,
                  colour=k.c["chip"], anchor=anchor)


# ── the diagrams ──────────────────────────────────────────────────────────

def architecture(scheme):
    """Two stages joined by one JSON file, and the three optional inputs to the second."""
    k = Canvas(1180, 544, scheme,
               "The collector reads every account's CloudTrail Event History through IAM "
               "Identity Center, and CloudTrail Lake adds data events; both write one event "
               "JSON file. The report stage turns it into the HTML dashboard, optionally with "
               "current state, a peer baseline and an external analysis.")
    W1, W2, W3, W4 = 232, 222, 236, 238
    x1, x2, x3, x4 = 44, 372, 638, 918
    H, r1, r2, mid, r3 = 92, 84, 220, 152, 372
    y = mid + H / 2
    k.add(
        k.group(24, 44, 272, 288, "COLLECT FROM AWS"),
        card(k, x1, r1, W1, H, "Event History", ["aws_offboarding_audit.py", "every account, via Identity Center"],
             mono=[0], icon="cloud"),
        card(k, x1, r2, W1, H, "CloudTrail Lake", ["aws_cloudtrail_lake.py", "data events, SQL or an export"],
             mono=[0], icon="database"),
        card(k, x2, mid, W2, H, "Event JSON", ["aws_offboarding_audit.json", "one normalised contract"],
             mono=[0], icon="document"),
        card(k, x3, mid, W3, H, "Report", ["aws_audit_report.py", "detectors, review priority"],
             mono=[0], icon="chip", tone="accent"),
        card(k, x4, mid, W4, H, "HTML dashboard", ["aws_offboarding_report.html", "plus Markdown and a summary"],
             mono=[0], icon="chart"),
        card(k, x2, r3, W2, H, "Current state", ["aws_current_state.py", "does it still exist?"],
             mono=[0], icon="shield"),
        card(k, x3, r3, W3, H, "Peer baseline", ["audit_baseline.py", "three or more peer audits"],
             mono=[0], icon="users"),
        card(k, x4, r3, W4, H, "External analysis", ["audit_analyst.py", "redacted digest, advisory"],
             mono=[0], icon="chat"),
        # Both collectors feed the same contract.
        k.edge([(x1 + W1 + 8, r1 + H / 2), (x2 - 8, y - 14)]),
        k.edge([(x1 + W1 + 8, r2 + H / 2), (x2 - 8, y + 14)]),
        k.edge([(x2 + W2 + 8, y), (x3 - 8, y)]),
        k.edge([(x3 + W3 + 8, y), (x4 - 8, y)]),
        # The three optional inputs, each named by the flag that passes it.
        k.edge([(x2 + W2 / 2, mid + H + 8), (x2 + W2 / 2, r3 - 8)]),
        note(k, x2 + W2 / 2 + 10, (mid + H + r3) / 2 + 4, "flagged resources", mono=False),
        k.edge([(x2 + W2 + 8, r3 + H / 2), (x3 + 40, mid + H + 8)]),
        note(k, x3 + 16, (mid + H + r3) / 2 + 4, "--state"),
        k.edge([(x3 + W3 / 2, r3 - 8), (x3 + W3 / 2, mid + H + 8)]),
        note(k, x3 + W3 / 2 + 10, (mid + H + r3) / 2 + 4, "--baseline"),
        k.edge([(x3 + W3 - 40, mid + H + 8), (x4 - 8, r3 + H / 2)], dash=True, both=True),
        note(k, x4 - 30, (mid + H + r3) / 2 + 4, "--analyze"),
        k.footer("Collection and reporting are separate: the dashboard rebuilds from saved event "
                 "JSON without querying AWS again, and every AWS call either stage makes is a read."),
    )
    return k.render()


DIAGRAMS = {
    "architecture": architecture,
}


def main() -> None:
    out = ROOT / "docs" / "assets"
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in DIAGRAMS.items():
        for scheme in SCHEMES:
            path = out / f"{name}-{scheme}.svg"
            path.write_text(fn(scheme), encoding="utf-8")
    print(f"{len(DIAGRAMS)} diagrams x {len(SCHEMES)} schemes -> docs/assets/")


if __name__ == "__main__":
    main()
