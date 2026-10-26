#!/usr/bin/env python3
"""Take the README screenshots of the report from synthetic data.

    make screenshots
    .venv-screenshots/bin/python tools/screenshots/take_screenshots.py

1. Writes the synthetic sample (tests/fixtures/gen_sample.py) into a temporary
   directory: fake account IDs, the user leaver@example.com, documentation IP
   ranges. No AWS call is made and nothing outside the temporary directory is
   touched.
2. Builds the dashboard from it with src/aws_audit_report.py (--no-enrich, so
   the build needs no network).
3. Opens the HTML file in Chromium through Playwright and photographs the
   Summary, Actions and evidence, and How to read pages at 1440x900.

The report has one colour scheme (light), so there are no dark variants.
Every image is docs/assets/screenshots/report-<page>-light.png, re-saved
without metadata and quantised to 256 colours. The report links IBM Plex from
Google Fonts; offline, the browser falls back to a system font.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "assets" / "screenshots"
PAGES = {"summary": "Summary", "findings": "Actions & evidence", "guide": "How to read"}


def build_report(workdir: Path) -> Path:
    subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fixtures" / "gen_sample.py")],
        cwd=workdir, check=True, stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            sys.executable, str(ROOT / "src" / "aws_audit_report.py"), "sample.json",
            "--user", "leaver@example.com",
            "--notice-date", "2026-07-24", "--last-day", "2026-08-15",
            "--org-accounts", "111122223333", "444455556666", "777788889999", "222233334444",
            "--state", "sample.state.json", "--baseline", "sample.baseline.json",
            "--no-enrich", "--out", "report",
        ],
        cwd=workdir, check=True, stdout=subprocess.DEVNULL,
    )
    return workdir / "report.html"


def save_clean(png: Path) -> None:
    """Re-save without any metadata chunks, in 256 colours."""
    with Image.open(png) as img:
        img.convert("RGB").quantize(256).save(png, optimize=True)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp, sync_playwright() as pw:
        report = build_report(Path(tmp))
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(report.as_uri())
        page.wait_for_timeout(800)
        for slug, label in PAGES.items():
            page.get_by_role("link", name=label, exact=True).first.click()
            page.wait_for_timeout(400)
            page.evaluate("window.scrollTo(0, 0)")
            target = OUT / f"report-{slug}-light.png"
            page.screenshot(path=str(target))
            save_clean(target)
            print("wrote", target.relative_to(ROOT))
        browser.close()


if __name__ == "__main__":
    main()
