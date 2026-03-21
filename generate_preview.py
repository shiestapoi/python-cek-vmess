#!/usr/bin/env python3
"""
generate_preview.py — Screenshot HTML report for Open Graph preview image.

Captures an exact 1200×630 screenshot of the report hero + stats + first rows,
identical to what a visitor sees in their browser.

Requirements:
    pip install playwright
    playwright install chromium --with-deps

Usage:
    python generate_preview.py                              # default: report.html → preview.png
    python generate_preview.py -i site/index.html -o site/preview.png
    python generate_preview.py --width 1200 --height 630
    python generate_preview.py --full-page                  # capture entire page height
"""

import argparse
import os
import sys
import pathlib


def screenshot(
    html_path: str,
    out_path: str,
    width: int = 1200,
    height: int = 630,
    full_page: bool = False,
    quality: int = 92,
) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "[error] playwright not installed.\n"
            "  Run: pip install playwright && playwright install chromium --with-deps",
            file=sys.stderr,
        )
        sys.exit(1)

    html_abs = pathlib.Path(html_path).resolve()
    if not html_abs.exists():
        print(f"[error] HTML file not found: {html_path}", file=sys.stderr)
        sys.exit(1)

    file_url = html_abs.as_uri()
    is_png   = out_path.lower().endswith(".png")
    fmt      = "png" if is_png else "jpeg"

    print(f"  Source  : {html_path}", file=sys.stderr)
    print(f"  Output  : {out_path}  ({width}×{height}, {fmt})", file=sys.stderr)
    print(f"  Full page: {full_page}", file=sys.stderr)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        page = browser.new_page(
            viewport={"width": width, "height": height},
            device_scale_factor=1,
        )

        # Load the local HTML file
        page.goto(file_url, wait_until="networkidle", timeout=30_000)

        # Wait until the table rows are rendered (JS render is async)
        try:
            page.wait_for_selector("#rows tr", timeout=10_000)
        except Exception:
            pass  # no rows rendered yet (empty report) — still take screenshot

        # Hide interactive controls that look odd in a static preview:
        # search input focus ring, scrollbar, modal backdrop
        page.add_style_tag(content="""
            /* Preview overrides: clean look for OG image */
            input, select { pointer-events: none !important; }
            .tbl-scroll    { overflow: hidden !important; max-height: none !important; }
            .pager         { display: none !important; }
            ::-webkit-scrollbar { display: none !important; }
        """)

        # Small pause for any animations to settle
        page.wait_for_timeout(400)

        # Screenshot
        kwargs: dict = {
            "path": out_path,
            "full_page": full_page,
            "clip": None if full_page else {"x": 0, "y": 0, "width": width, "height": height},
        }
        if fmt == "jpeg":
            kwargs["type"] = "jpeg"
            kwargs["quality"] = quality

        page.screenshot(**kwargs)
        browser.close()

    size_kb = os.path.getsize(out_path) // 1024
    print(f"  [OK] Preview saved: {out_path}  ({size_kb} KB)", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate OG preview image (screenshot) from V2Ray HTML report."
    )
    parser.add_argument(
        "-i", "--input", default="report.html",
        help="Path to the generated HTML report (default: report.html)",
    )
    parser.add_argument(
        "-o", "--output", default="preview.png",
        help="Output image path, .png or .jpg (default: preview.png)",
    )
    parser.add_argument(
        "--width", type=int, default=1200,
        help="Viewport / image width in pixels (default: 1200)",
    )
    parser.add_argument(
        "--height", type=int, default=630,
        help="Viewport / image height in pixels (default: 630)",
    )
    parser.add_argument(
        "--full-page", action="store_true",
        help="Capture the entire scrollable page instead of just the viewport",
    )
    parser.add_argument(
        "--quality", type=int, default=92,
        help="JPEG quality 1-100 (ignored for PNG, default: 92)",
    )
    args = parser.parse_args()

    screenshot(
        html_path=args.input,
        out_path=args.output,
        width=args.width,
        height=args.height,
        full_page=args.full_page,
        quality=args.quality,
    )


if __name__ == "__main__":
    main()
