#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Desktop context is view/draft only and never calls localhost execute."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from desktop_context import (  # noqa: E402
    CONTEXT_TYPE,
    DesktopContextError,
    apply_desktop_context,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "desktop-context.example.json"


class TestDesktopContext(unittest.TestCase):
    def test_example_is_inspect_view(self):
        ctx = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        out = apply_desktop_context(ctx)
        self.assertEqual(ctx["type"], CONTEXT_TYPE)
        self.assertEqual(out["purpose"], "INSPECT")
        self.assertTrue(out["view_or_draft"])
        self.assertFalse(out["http"])
        self.assertFalse(out["localhost"])
        self.assertFalse(out["execute"])
        ids = [o["operation_id"] for o in out["operations"]]
        self.assertIn("getInstitutionalAsset", ids)
        self.assertNotIn("executeAllocation", ids)
        self.assertTrue(all(o["method"] == "GET" for o in out["operations"]))

    def test_draft_maps_to_prepare_not_execute(self):
        ctx = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        ctx["btx"]["purpose"] = "DRAFT"
        out = apply_desktop_context(ctx)
        self.assertEqual(out["operations"][0]["operation_id"], "preparePortfolioInstruction")
        self.assertIs(out["operations"][0]["body"]["execute"], False)
        self.assertFalse(out["execute"])

    def test_rejects_token(self):
        ctx = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        ctx["btx"]["access_token"] = "stolen"
        with self.assertRaises(DesktopContextError) as e:
            apply_desktop_context(ctx)
        self.assertEqual(e.exception.code, "SECRET_INLINE")

    def test_rejects_execute_purpose(self):
        ctx = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        ctx["btx"]["purpose"] = "EXECUTE"
        with self.assertRaises(DesktopContextError) as e:
            apply_desktop_context(ctx)
        self.assertEqual(e.exception.code, "VIEW_DRAFT_ONLY")

    def test_rejects_localhost_execute_url(self):
        ctx = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        ctx["btx"]["href"] = "http://127.0.0.1:8080/btx/hcp/v1/capital/allocations/x/execute"
        with self.assertRaises(DesktopContextError) as e:
            apply_desktop_context(ctx)
        self.assertEqual(e.exception.code, "LOCALHOST_EXECUTE_FORBIDDEN")

    def test_source_has_no_http_client(self):
        src = (HERE / "desktop_context.py").read_text(encoding="utf-8")
        self.assertNotIn("urllib", src)
        self.assertNotIn("http.client", src)
        self.assertNotIn("requests", src)
        self.assertNotIn("fetch(", src)

    def test_compare_is_view_only(self):
        ctx = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        ctx["btx"]["purpose"] = "COMPARE"
        out = apply_desktop_context(ctx)
        ids = [o["operation_id"] for o in out["operations"]]
        self.assertIn("listInstitutionalMetrics", ids)
        self.assertNotIn("executeAllocation", ids)
        self.assertFalse(out["execute"])
        self.assertTrue(all(o["method"] == "GET" for o in out["operations"]))

    def test_rejects_execute_now(self):
        ctx = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        ctx["btx"]["purpose"] = "EXECUTE_NOW"
        with self.assertRaises(DesktopContextError) as e:
            apply_desktop_context(ctx)
        self.assertEqual(e.exception.code, "VIEW_DRAFT_ONLY")


if __name__ == "__main__":
    unittest.main()
