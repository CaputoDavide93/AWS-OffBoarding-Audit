#!/usr/bin/env python3
"""Render docs/assets/brand/icon-256.png and docs/assets/social-preview.png.

    make brand

The icon is docs/assets/brand/icon.svg. To swap it, replace that file and run
`make brand`. Needs the screenshot environment (`make screenshots` builds it).
The images are re-saved without metadata. Upload social-preview.png by hand in
the repository settings (Social preview).
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "docs" / "assets" / "brand"
NAME = "AWS Offboarding Audit"
TAGLINE = "Check what a departing engineer did across every AWS account, in one local report"
CHIPS = ("Read-only AWS calls", "CloudTrail + Lake", "Local HTML dashboard", "Python 3.10+")

PAGE = """<!doctype html><meta charset=utf-8><style>
*{{box-sizing:border-box}}
body{{margin:0;width:1280px;height:640px;background:#16202A;color:#EEF1F4;
 font-family:-apple-system,"Helvetica Neue",Arial,sans-serif;position:relative;overflow:hidden}}
.grid{{position:absolute;inset:0;background-image:linear-gradient(rgba(238,241,244,.04) 1px,transparent 1px),
 linear-gradient(90deg,rgba(238,241,244,.04) 1px,transparent 1px);background-size:32px 32px}}
.wrap{{position:absolute;left:96px;top:0;bottom:0;right:96px;display:flex;flex-direction:column;justify-content:center}}
img{{width:140px;height:140px;border-radius:32px;box-shadow:0 0 0 2px rgba(238,241,244,.18)}}
h1{{font-size:84px;line-height:1.05;margin:36px 0 18px;letter-spacing:-1px}}
p{{font-size:34px;line-height:1.3;margin:0;color:#B9C4CF;max-width:1000px}}
.chips{{display:flex;gap:14px;margin-top:44px}}
.chip{{white-space:nowrap;font:600 22px ui-monospace,Menlo,monospace;color:#FF9900;border:2px solid #FF9900;border-radius:999px;padding:8px 22px}}
</style><div class=grid></div><div class=wrap>
<img src="{icon}"><h1>{name}</h1><p>{tagline}</p>
<div class=chips>{chips}</div></div>"""


def clean(path: Path) -> None:
    with Image.open(path) as img:
        img.convert("RGB").quantize(256).save(path, optimize=True)


def main() -> None:
    icon = BRAND / "icon.svg"
    html = PAGE.format(
        icon=icon.as_uri(), name=NAME, tagline=TAGLINE,
        chips="".join(f"<span class=chip>{c}</span>" for c in CHIPS),
    )
    page_file = BRAND / ".social.html"
    page_file.write_text(html, encoding="utf-8")
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 640})
            page.goto(page_file.as_uri())
            page.wait_for_timeout(300)
            page.screenshot(path=str(ROOT / "docs" / "assets" / "social-preview.png"))
            page.set_viewport_size({"width": 256, "height": 256})
            page.set_content(
                f'<body style="margin:0"><img src="{icon.as_uri()}" width=256 height=256>'
            )
            page.wait_for_timeout(300)
            page.screenshot(path=str(BRAND / "icon-256.png"), omit_background=True)
            browser.close()
    finally:
        page_file.unlink(missing_ok=True)
    clean(ROOT / "docs" / "assets" / "social-preview.png")
    with Image.open(BRAND / "icon-256.png") as img:
        img.convert("RGBA").save(BRAND / "icon-256.png", optimize=True)
    print("wrote docs/assets/social-preview.png and docs/assets/brand/icon-256.png")


if __name__ == "__main__":
    main()
