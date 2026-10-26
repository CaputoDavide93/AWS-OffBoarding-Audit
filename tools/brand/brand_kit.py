#!/usr/bin/env python3
"""Vendored copy of the CaputoDavide93 brand kit, trimmed to this repo: one icon tile + one social preview layout for every repo.

  python3 brand_kit.py icon   --repo NAME [--out DIR] [--sizes 256,64]
  python3 brand_kit.py icon   --glyph FILE --hue 200 --out DIR
  python3 brand_kit.py social --repo NAME --tagline TEXT --chip A --chip B [--icon icon.svg] --out out.png
  python3 brand_kit.py sheet  [--repos A,B,...] --out sheet.png
  python3 brand_kit.py all    [--out DIR]
Needs headless Google Chrome and Pillow. Rendering is deterministic; PNG metadata is stripped.
"""
import argparse, colorsys, html, os, pathlib, subprocess, sys, tempfile
from PIL import Image

HERE = pathlib.Path(__file__).resolve().parent
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
INK = "#F8FAFC"

# Family order. Hue steps by 12 slots (12 is coprime with 29), so every repo gets its own
# hue and neighbours in this list are ~140 degrees apart. Slots span 100..400 degrees: the
# muddy 40-100 yellow/olive band, where a white glyph cannot hold contrast, is skipped.
REPOS = ["AWS-Offboarding-Audit"]
def hue_of(repo):
    return 172  # fixed hue for this repo

# ---- colour -----------------------------------------------------------------
def _lum(rgb):
    f = lambda c: c / 12.92 if c <= .03928 else ((c + .055) / 1.055) ** 2.4
    r, g, b = (f(c) for c in rgb)
    return .2126 * r + .7152 * g + .0722 * b
def _hex(h, s, l):
    r, g, b = colorsys.hls_to_rgb(h / 360, l, s)
    return "#%02X%02X%02X" % (round(r * 255), round(g * 255), round(b * 255)), (r, g, b)
def _contrast(rgb):  # against near-white ink
    return (_lum((.97, .98, .99)) + .05) / (_lum(rgb) + .05)
def palette(hue):
    """(top, bottom, mid) hex. Same saturation, lightness 54/40; yellows and greens are
    darkened just enough that the white glyph keeps 3.2:1 (top) and 4.5:1 (bottom)."""
    s, lt, lb = .68, .55, .41
    while _contrast(_hex(hue, s, lt)[1]) < 3.2 and lt > .30: lt -= .01
    while _contrast(_hex(hue, s, lb)[1]) < 4.5 and lb > .20: lb -= .01
    lb = min(lb, lt - .12)
    return _hex(hue, s, lt)[0], _hex(hue, s, lb)[0], _hex(hue, s, (lt + lb) / 2)[0]
def dark_bg(hue):
    return _hex(hue, .38, .10)[0], _hex(hue, .45, .06)[0]

# ---- rendering --------------------------------------------------------------
def render(html_doc, w, h, out, transparent=False):
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "p.html"
        p.write_text(html_doc)
        shot = pathlib.Path(td) / "s.png"
        cmd = [CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-sandbox",
               "--force-device-scale-factor=1", f"--window-size={w},{h}",
               "--virtual-time-budget=3000", f"--screenshot={shot}", f"file://{p}"]
        if transparent: cmd.insert(2, "--default-background-color=00000000")
        subprocess.run(cmd, check=True, capture_output=True)
        im = Image.open(shot).convert("RGBA" if transparent else "RGB")
    # fresh image = no metadata chunks
    clean = Image.new(im.mode, im.size); clean.paste(im)
    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    clean.save(out, optimize=True)
    return clean

def icon_svg(glyph_fragment, hue):
    top, bot, _ = palette(hue)
    gid = f"g{hue}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">'
            f'<defs><linearGradient id="{gid}" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0" stop-color="{top}"/><stop offset="1" stop-color="{bot}"/></linearGradient></defs>'
            f'<rect width="1024" height="1024" rx="225" fill="url(#{gid})"/>\n{glyph_fragment.strip()}\n</svg>\n')

def make_icon(glyph_svg_fragment, hue, out_svg, out_png_sizes=(256,)):
    """glyph fragment is drawn in a 1024 space; out_png_sizes -> files icon-<n>.png beside out_svg
    (a dict {size: path} is also accepted)."""
    out_svg = pathlib.Path(out_svg).resolve(); out_svg.parent.mkdir(parents=True, exist_ok=True)
    svg = icon_svg(glyph_svg_fragment, hue); out_svg.write_text(svg)
    sizes = out_png_sizes if isinstance(out_png_sizes, dict) else {n: out_svg.parent / f"icon-{n}.png" for n in out_png_sizes}
    if sizes:
        big = render(f'<body style="margin:0;background:transparent"><img src="file://{out_svg}" width=1024 height=1024 style="display:block">',
                     1024, 1024, out_svg.parent / ".icon-1024.tmp.png", transparent=True)
        (out_svg.parent / ".icon-1024.tmp.png").unlink()
        for n, path in sizes.items():
            c = big.resize((int(n), int(n)), Image.LANCZOS)
            pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
            c.save(path, optimize=True)
    return svg

def make_social(name, tagline, chips, icon_svg_path, hue, out_png):
    """1280x640, tile left, name, tagline, chips, hue stripe. Same layout for every repo."""
    top, bot, mid = palette(hue); d1, d2 = dark_bg(hue)
    chips = list(chips)[:4]
    chip_html = "".join(f'<span class="c{" f" if i == 0 else ""}">{html.escape(c)}</span>' for i, c in enumerate(chips))
    doc = f'''<!doctype html><meta charset=utf-8><style>
*{{box-sizing:border-box;margin:0}}
body{{width:1280px;height:640px;overflow:hidden;font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;color:{INK};
 background:radial-gradient(900px 600px at 18% 45%,{mid}33,transparent 70%),linear-gradient(135deg,{d1},{d2});position:relative}}
.tile{{position:absolute;left:98px;top:170px;width:300px;height:300px;border-radius:22%;box-shadow:0 0 0 2px #ffffff1f}}
.txt{{position:absolute;left:480px;top:0;width:740px;height:632px;display:flex;flex-direction:column;justify-content:center}}
h1{{font-weight:800;letter-spacing:-.025em;line-height:1.02;white-space:nowrap;font-size:96px;margin-bottom:26px}}
h1.wrap{{white-space:normal;font-size:68px;overflow-wrap:anywhere}}
p{{font-size:35px;line-height:1.28;font-weight:600;color:#E3E6EBd9;margin-bottom:38px;letter-spacing:-.005em}}
.chips{{display:flex;gap:12px;flex-wrap:wrap}}
.c{{font-weight:700;font-size:23px;padding:11px 22px;border-radius:99px;border:2px solid #ffffff33;color:#F1F3F6}}
.c.f{{background:linear-gradient(180deg,{top},{bot});border-color:transparent;color:#fff}}
.bar{{position:absolute;left:0;right:0;bottom:0;height:8px;background:linear-gradient(90deg,{top},{bot})}}
</style><img class=tile src="file://{pathlib.Path(icon_svg_path).resolve()}">
<div class=txt><h1 id=n>{html.escape(name)}</h1><p>{html.escape(tagline)}</p><div class=chips>{chip_html}</div></div><div class=bar></div>
<script>const h=document.getElementById('n');let s=96;while(h.scrollWidth>740&&s>60){{s-=2;h.style.fontSize=s+'px'}}
if(h.scrollWidth>740){{h.className='wrap';h.innerHTML=h.textContent.replace(/-/g,'-<wbr>')}}</script>'''
    return render(doc, 1280, 640, out_png)

def make_sheet(repos, out_png, icon_dir=None):
    """Labelled contact sheet: 256 px grids on light and dark, then a 64/32/16 row on both."""
    icon_dir = pathlib.Path(icon_dir or HERE / "out")
    def cell(r, bg, fg, px):
        return (f'<figure><img src="file://{icon_dir / r / "icon.svg"}" width={px} height={px}>'
                f'<figcaption style="color:{fg}">{html.escape(r)}</figcaption></figure>')
    def small(r, bg, fg):
        im = lambda px: f'<img src="file://{icon_dir / r / "icon.svg"}" width={px} height={px}>'
        return (f'<div class=s style="background:{bg};color:{fg}"><div class=row>{im(64)}{im(32)}{im(16)}</div>'
                f'<span>{html.escape(r)}</span></div>')
    L, D = ("#F3F4F6", "#1B1D22"), ("#101218", "#C9CDD6")
    big = lambda bg, fg, t: (f'<section style="background:{bg}"><h2 style="color:{fg}">{t}</h2><div class=g>'
                             + "".join(cell(r, bg, fg, 256) for r in repos) + '</div></section>')
    smalls = ('<section style="background:#fff"><h2 style="color:#1B1D22">64 / 32 / 16 px, light and dark</h2><div class=sg>'
              + "".join(small(r, L[0], L[1]) + small(r, D[0], D[1]) for r in repos) + '</div></section>')
    cols = 6
    doc = f'''<!doctype html><meta charset=utf-8><style>
*{{box-sizing:border-box;margin:0}} body{{width:1900px;font-family:"Helvetica Neue",Arial,sans-serif}}
section{{padding:48px 60px}} h2{{font-size:26px;font-weight:700;margin-bottom:28px;letter-spacing:-.01em}}
.g{{display:grid;grid-template-columns:repeat({cols},1fr);gap:40px 24px}}
figure{{display:flex;flex-direction:column;align-items:center;gap:12px}} figcaption{{font-size:15px;font-weight:600}}
.sg{{display:grid;grid-template-columns:repeat(4,1fr);gap:0}}
.s{{display:flex;align-items:center;justify-content:space-between;padding:14px 22px;font-size:14px;font-weight:600;height:84px}}
.row{{display:flex;align-items:center;gap:14px;flex:none;margin-right:16px}}
</style>{big(L[0], L[1], "Light background, 256 px")}{big(D[0], D[1], "Dark background, 256 px")}{smalls}'''
    # first pass to measure height
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "m.html"; p.write_text(doc + '<script>document.title=document.documentElement.scrollHeight</script>')
        out = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", f"--window-size=1900,800",
                              "--virtual-time-budget=2000", "--dump-dom", f"file://{p}"], capture_output=True, text=True).stdout
    import re
    h = int(re.search(r"<title>(\d+)</title>", out).group(1))
    return render(doc, 1900, h, out_png)

# ---- CLI --------------------------------------------------------------------
def _glyph(repo): return (HERE / "glyphs" / f"{repo}.svg").read_text()

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("icon"); a.add_argument("--repo"); a.add_argument("--glyph"); a.add_argument("--hue", type=int)
    a.add_argument("--out", default="."); a.add_argument("--sizes", default="256")
    b = sub.add_parser("social"); b.add_argument("--repo"); b.add_argument("--name"); b.add_argument("--tagline", required=True)
    b.add_argument("--chip", action="append", default=[]); b.add_argument("--icon", default="docs/assets/brand/icon.svg")
    b.add_argument("--hue", type=int); b.add_argument("--out", default="docs/assets/social-preview.png")
    c = sub.add_parser("sheet"); c.add_argument("--repos"); c.add_argument("--out", default="family-sheet.png")
    c.add_argument("--icons", help="dir holding <repo>/icon.svg")
    d = sub.add_parser("all"); d.add_argument("--out", default=str(HERE / "out"))
    n = ap.parse_args(argv)
    if n.cmd == "icon":
        frag = pathlib.Path(n.glyph).read_text() if n.glyph else _glyph(n.repo)
        hue = n.hue if n.hue is not None else hue_of(n.repo)
        sizes = [int(x) for x in n.sizes.split(",") if x]
        make_icon(frag, hue, pathlib.Path(n.out) / "icon.svg", sizes)
    elif n.cmd == "social":
        hue = n.hue if n.hue is not None else hue_of(n.repo)
        make_social(n.name or n.repo, n.tagline, n.chip, n.icon, hue, n.out)
    elif n.cmd == "sheet":
        repos = n.repos.split(",") if n.repos else REPOS
        make_sheet(repos, n.out, n.icons)
    else:
        out = pathlib.Path(n.out)
        for r in REPOS:
            make_icon(_glyph(r), hue_of(r), out / r / "icon.svg", [256])
        make_sheet(REPOS, out / "family-sheet.png", out)
        print("hue table:"); [print(f"  {r:34s}{hue_of(r):4d}") for r in REPOS]

if __name__ == "__main__":
    sys.exit(main())
