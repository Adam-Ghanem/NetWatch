"""Capture actual NetWatch UI pages from a running local FastAPI instance.

Run only in a disposable CI environment with synthetic data and a test-only key.
"""

from __future__ import annotations

import os
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:8000"
OUT = Path("screenshots-captured")
OUT.mkdir(exist_ok=True)


def main() -> None:
    key = os.environ["NETWATCH_API_KEY"]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=["--no-sandbox"])
        page = browser.new_page(
            viewport={"width": 1440, "height": 950},
            device_scale_factor=1,
            color_scheme="light",
        )
        page.goto(BASE_URL, wait_until="domcontentloaded", timeout=30000)
        page.locator("#api-key").fill(key)
        page.locator('#connect-form button[type="submit"]').click()
        page.locator("#connect-overlay.hidden").wait_for(timeout=30000)
        page.locator('#view-overview.active').wait_for(timeout=30000)
        page.wait_for_timeout(1250)

        for view, filename in (
            ("overview", "overview.png"),
            ("advisor", "risk-advisor.png"),
            ("ports", "port-audit.png"),
        ):
            if view != "overview":
                page.locator(f'#nav button[data-view="{view}"]').click()
                page.locator(f"#view-{view}.active").wait_for(timeout=20000)
                page.wait_for_timeout(550)
            page.screenshot(path=str(OUT / filename), full_page=True, animations="disabled")
            print("Captured:", filename)
        browser.close()


if __name__ == "__main__":
    main()
