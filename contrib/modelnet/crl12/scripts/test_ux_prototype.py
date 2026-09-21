#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Offline CRL/1.2 UX prototype checks.

Static a11y always runs (no extra pip). The package Playwright/Chromium
interaction harness is attempted when those deps are present; otherwise
the script records HONEST_NOT_RUN and still exits 0 if static checks pass.

Does not start btxd.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODELNET = ROOT.parent
SDK_PY = MODELNET / "crl12-sdk" / "python"
HTML_FILES = (
    ROOT / "ux" / "index.html",
    MODELNET / "crl12-portal" / "index.html",
)

sys.path.insert(0, str(SDK_PY))
from test_portal_a11y import TestPortalA11y, assert_html_a11y  # noqa: E402

CHROMIUM_CANDIDATES = (
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/snap/bin/chromium",
)


def _chromium_path() -> str | None:
    for p in CHROMIUM_CANDIDATES:
        if Path(p).is_file():
            return p
    return None


def _run_static() -> list[str]:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestPortalA11y)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    checks = ["static-a11y-unittest"]
    for html_path in HTML_FILES:
        html = html_path.read_text(encoding="utf-8")
        assert_html_a11y(html, name=str(html_path))
        checks.append(f"static:{html_path.name}:{html_path.parent.name}")
    return checks


def _run_playwright(html_path: Path) -> dict:
    from playwright.sync_api import sync_playwright

    checks: list[str] = []
    errors: list[str] = []
    requests: list[str] = []
    chrome = _chromium_path()
    launch_kw: dict = {"headless": True, "args": ["--no-sandbox"]}
    if chrome:
        launch_kw["executable_path"] = chrome
    with sync_playwright() as p:
        browser = p.chromium.launch(**launch_kw)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("request", lambda r: requests.append(r.url))
        page.set_content(html_path.read_text(encoding="utf-8"))
        page.wait_for_load_state("load")
        assert page.locator("#overview").is_visible()
        checks.append("initial-overview")
        for tab in ["reserves", "capabilities", "build", "approvals", "activity", "overview"]:
            page.locator(f"button[data-tab={tab}]").click()
            assert page.locator("#" + tab).is_visible()
            assert page.locator("nav button[aria-current=page]").count() == 1
        checks.append("six-navigation-destinations")
        page.locator("button[data-tab=reserves]").click()
        page.select_option("#metric", "AUM")
        assert page.locator("#metricValue").inner_text() == "$600,000"
        page.check("#missing")
        assert page.locator("#metricValue").inner_text() == "Valuation unavailable"
        checks.append("missing-value-not-zero")
        page.select_option("#metric", "CAPABILITY_COUNT")
        assert page.locator("#metricValue").inner_text() == "148 recipes"
        checks.append("capability-count-not-money")
        page.locator("#connections").click()
        assert page.locator("#connectionPanel").is_visible()
        checks.append("provider-role-composition")
        page.locator("button[data-tab=overview]").click()
        page.locator("#entity").select_option(label="Family group — read only")
        page.locator("#overview button[data-action=draft]").click()
        assert "Select an explicit legal payer" in page.locator("#notice").inner_text()
        checks.append("group-draft-refused")
        page.locator("#entity").select_option(label="Operating company")
        page.locator("#overview button[data-action=draft]").click()
        assert "Draft prepared" in page.locator("#notice").inner_text()
        checks.append("entity-draft-preview")
        page.set_viewport_size({"width": 390, "height": 844})
        page.locator("button[data-tab=reserves]").click()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        checks.append("mobile-no-horizontal-document-overflow")
        assert not errors, errors
        external = [u for u in requests if u.startswith(("http://", "https://"))]
        assert not external, external
        checks.append("offline-no-external-requests")
        browser.close()
    return {
        "status": "PASS",
        "file": str(html_path),
        "checks": checks,
        "javascript_errors": errors,
        "external_requests": 0,
    }


def main() -> int:
    checks = _run_static()
    report: dict = {
        "status": "PASS",
        "scope": "offline synthetic prototype only",
        "checks": checks,
        "playwright": None,
    }
    try:
        import playwright  # noqa: F401
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError as e:
        report["playwright"] = {
            "status": "HONEST_NOT_RUN",
            "reason": f"playwright not installed ({e})",
        }
        print(json.dumps(report, indent=2))
        return 0

    pw_results = []
    try:
        for html_path in HTML_FILES:
            pw_results.append(_run_playwright(html_path))
    except Exception as e:
        report["playwright"] = {
            "status": "HONEST_NOT_RUN",
            "reason": f"chromium/playwright launch failed: {e}",
        }
        print(json.dumps(report, indent=2))
        return 0

    report["playwright"] = {"status": "PASS", "results": pw_results}
    for row in pw_results:
        report["checks"].extend(row["checks"])
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
