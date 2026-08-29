#!/usr/bin/env python3
"""Issue 116: every production mint/persist site must be accounted for.

Patching one SignAuthoritative call and declaring victory is how this
survived the last round. This inventory fails closed if a new production
call appears, or if a net_processing PersistMatMulExactReplayVerdict call
no longer gossips in the following window.

AcceptBlock (validation.cpp) mints via Persist without a P2P publish in
the same function. That is a listed finding, not a silent skip: RPC
generate/submitblock go through ProcessNewBlock only, not ProcessBlockSync.
"""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "src"

# Production files allowed to mention SignAuthoritative( (definition or call).
ALLOWED_SIGN_FILES = {
    SRC / "node" / "matmul_trusted_attestations.cpp",
    SRC / "node" / "matmul_trusted_attestations.h",
    SRC / "validation.cpp",
    SRC / "net_processing.cpp",
    SRC / "rpc" / "matmul_trusted.cpp",
}
REQUIRED_SIGN_CALL_FILES = {
    SRC / "validation.cpp",
    SRC / "net_processing.cpp",
    SRC / "rpc" / "matmul_trusted.cpp",
}

SIGN_CALL = re.compile(r"\bSignAuthoritative\s*\(")
PERSIST_CALL = re.compile(r"\bPersistMatMulExactReplayVerdict\s*\(")
DEFINITION = re.compile(
    r"^(bool ChainstateManager::PersistMatMulExactReplayVerdict|"
    r"matmul::trusted::AddResult SignAuthoritative|"
    r"\[\[nodiscard\]\] matmul::trusted::AddResult SignAuthoritative)"
)


def production_cpp_h() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for path in SRC.rglob("*"):
        if not path.is_file() or path.suffix not in {".cpp", ".h"}:
            continue
        if any(part == "test" for part in path.relative_to(SRC).parts):
            continue
        out.append(path)
    return sorted(out)


def calls_in(path: pathlib.Path, pattern: re.Pattern[str]) -> list[int]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    hits: list[int] = []
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if DEFINITION.search(stripped):
            continue
        if pattern.search(line):
            hits.append(i)
    return hits


def window_has_relay(path: pathlib.Path, line_no: int, depth: int = 24) -> bool:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    chunk = "\n".join(lines[line_no - 1 : line_no - 1 + depth])
    return "RelayLocalExactReplayAttestation" in chunk


class Issue116AttestationPublishSitesTest(unittest.TestCase):
    def test_production_signauthoritative_call_files_are_exactly_the_known_set(self) -> None:
        found: dict[pathlib.Path, list[int]] = {}
        for path in production_cpp_h():
            hits = calls_in(path, SIGN_CALL)
            if hits:
                found[path] = hits
        unexpected = sorted(p for p in found if p not in ALLOWED_SIGN_FILES)
        missing = sorted(p for p in REQUIRED_SIGN_CALL_FILES if p not in found)
        self.assertFalse(
            unexpected,
            "new production SignAuthoritative site(s) without an inventory "
            "entry (file:line): "
            + ", ".join(f"{p.relative_to(ROOT)}:{found[p]}" for p in unexpected),
        )
        self.assertFalse(
            missing,
            "expected SignAuthoritative production file vanished: "
            + ", ".join(str(p.relative_to(ROOT)) for p in missing),
        )

    def test_signauthoritative_call_counts(self) -> None:
        # Definition + each production call. Line numbers are asserted as
        # counts so a new call in a known file still fails.
        self.assertEqual(
            calls_in(SRC / "validation.cpp", SIGN_CALL),
            [13701],
            "PersistMatMulExactReplayVerdict must be the only validation.cpp mint",
        )
        self.assertEqual(
            calls_in(SRC / "net_processing.cpp", SIGN_CALL),
            [13824, 17538, 17589],
            "net_processing SignAuthoritative sites changed",
        )
        self.assertEqual(
            calls_in(SRC / "rpc" / "matmul_trusted.cpp", SIGN_CALL),
            [464],
            "rpc/matmul_trusted.cpp SignAuthoritative sites changed",
        )

    def test_net_processing_persist_callers_gossip(self) -> None:
        persist = calls_in(SRC / "net_processing.cpp", PERSIST_CALL)
        self.assertEqual(
            persist,
            [10316, 10988, 11144, 12701, 13722],
            "net_processing PersistMatMulExactReplayVerdict sites changed; "
            f"found {persist}",
        )
        missing = [n for n in persist if not window_has_relay(SRC / "net_processing.cpp", n)]
        self.assertFalse(
            missing,
            "PersistMatMulExactReplayVerdict without RelayLocalExactReplayAttestation "
            f"in the next 24 lines: {missing}",
        )

    def test_acceptblock_persist_has_no_p2p_publish_in_window(self) -> None:
        persist = calls_in(SRC / "validation.cpp", PERSIST_CALL)
        self.assertEqual(
            persist,
            [14879],
            f"validation.cpp persist call sites changed: {persist}",
        )
        self.assertFalse(
            window_has_relay(SRC / "validation.cpp", 14879),
            "AcceptBlock persist grew a gossip call; update the Issue 116 "
            "inventory if that is now the publish path",
        )

    def test_processblocksync_and_getmmattest_push_after_sign(self) -> None:
        net = SRC / "net_processing.cpp"
        self.assertTrue(window_has_relay(net, 13824))
        # GETMMATTEST regen / covered-sign both fall through to push_mmattest.
        lines = net.read_text(encoding="utf-8").splitlines()
        after_regen = "\n".join(lines[17537:17640])
        self.assertIn("push_mmattest", after_regen)
        after_covered = "\n".join(lines[17588:17640])
        self.assertIn("push_mmattest", after_covered)


if __name__ == "__main__":
    unittest.main()
