#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Static CRL/1.2 portal/UX a11y checks. No browser, no network, no btxd.

Validates contrib/modelnet/crl12-portal/index.html and crl12/ux/index.html:
44px targets, aria-live, family-group read-only, offline prototype.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODELNET = HERE.parents[1]
PORTAL = MODELNET / "crl12-portal" / "index.html"
UX = MODELNET / "crl12" / "ux" / "index.html"

TABS = ("overview", "reserves", "capabilities", "build", "approvals", "activity")
FORBIDDEN_NETWORK = (
    "fetch(",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "sendBeacon",
    "navigator.sendBeacon",
    "http://",
    "https://",
    "ws://",
    "wss://",
)
FORBIDDEN_MONEY = (
    "executeAllocation",
    "/rpc",
    "access_token",
    "CR12_SEC_SENTINEL",
    "wallet.dat",
    "BEGIN PRIVATE",
)


def assert_html_a11y(html: str, *, name: str = "html") -> None:
    if not html.strip():
        raise AssertionError(f"{name} is empty")
    for needle in FORBIDDEN_NETWORK:
        if needle in html:
            raise AssertionError(f"{name} must stay offline; found {needle!r}")
    for needle in FORBIDDEN_MONEY:
        if needle in html:
            raise AssertionError(f"{name} must not carry {needle!r}")
    if "min-height:44px" not in html:
        raise AssertionError(f"{name} missing 44px min-height targets")
    if "label{min-height:44px" not in html and "label{min-height: 44px" not in html:
        raise AssertionError(f"{name} labels must be at least 44px")
    if 'aria-live="polite"' not in html and "aria-live='polite'" not in html:
        raise AssertionError(f"{name} missing aria-live")
    if 'aria-atomic="true"' not in html and "aria-atomic='true'" not in html:
        raise AssertionError(f"{name} missing aria-atomic on the live region")
    if 'role="status"' not in html:
        raise AssertionError(f"{name} missing role=status")
    if 'id="notice"' not in html:
        raise AssertionError(f"{name} missing #notice")
    if "Family group" not in html or "read only" not in html:
        raise AssertionError(f"{name} missing family-group read-only option")
    if "selectedIndex===2" not in html and "selectedIndex === 2" not in html:
        raise AssertionError(f"{name} missing family-group draft refusal")
    if "Select an explicit legal payer" not in html:
        raise AssertionError(f"{name} missing payer-required copy")
    if 'aria-label="Primary"' not in html:
        raise AssertionError(f"{name} missing primary nav name")
    if "focus-visible" not in html:
        raise AssertionError(f"{name} missing visible focus")
    if "Skip to content" not in html:
        raise AssertionError(f"{name} missing skip link")
    if "Partial view" not in html or "Valuation unavailable" not in html:
        raise AssertionError(f"{name} missing partial-view copy")
    if "signed manifest" not in html:
        raise AssertionError(f"{name} missing export manifest copy")
    if "no network, signing, funding or local runtime execution" not in html:
        raise AssertionError(f"{name} missing offline prototype notice")
    for tab in TABS:
        if f'data-tab="{tab}"' not in html:
            raise AssertionError(f"{name} missing destination {tab}")
    if 'id="entity"' not in html:
        raise AssertionError(f"{name} missing entity selector")
    if re.search(r"""<script\s+src=["'][^#]""", html, re.I):
        raise AssertionError(f"{name} must not load an external script")
    if "draft" not in html.lower():
        raise AssertionError(f"{name} missing draft-only action copy")


class TestPortalA11y(unittest.TestCase):
    def test_portal_and_ux_exist_and_match(self):
        self.assertTrue(PORTAL.is_file(), str(PORTAL))
        self.assertTrue(UX.is_file(), str(UX))
        portal = PORTAL.read_text(encoding="utf-8")
        ux = UX.read_text(encoding="utf-8")
        self.assertEqual(portal, ux, "crl12-portal must stay a copy of crl12/ux")

    def test_portal_a11y_contract(self):
        assert_html_a11y(PORTAL.read_text(encoding="utf-8"), name="crl12-portal")

    def test_ux_a11y_contract(self):
        assert_html_a11y(UX.read_text(encoding="utf-8"), name="crl12/ux")

    def test_family_group_refuses_financial_drafts_only(self):
        html = PORTAL.read_text(encoding="utf-8")
        self.assertIn("['draft','research','bind']", html)
        self.assertIn("cannot create this draft", html)


if __name__ == "__main__":
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    unittest.main()
