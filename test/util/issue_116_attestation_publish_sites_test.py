#!/usr/bin/env python3
"""Issue 116: every production mint/persist site must be accounted for.

Patching one SignAuthoritative call and declaring victory is how this
survived the last round. This inventory fails closed if a new production
call appears, or if a net_processing PersistMatMulExactReplayVerdict call
no longer gossips in the following window.

AcceptBlock (validation.cpp) still mints via Persist without a P2P publish
in the same function (validation must not gossip). generate/submitblock
are covered by ProcessNewBlock -> ProcessNewBlockFinished ->
MaybeRelayLocalExactReplayAttestation -> RelayLocalExactReplayAttestation.
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


def function_contains(path: pathlib.Path, func_name: str, needle: str) -> bool:
    text = path.read_text(encoding="utf-8")
    marker = f"PeerManagerImpl::{func_name}("
    start = text.find(marker)
    if start < 0:
        return False
    nxt = text.find("\nvoid PeerManagerImpl::", start + len(marker))
    body = text[start : nxt if nxt >= 0 else start + 4000]
    return needle in body


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
        val_hits = calls_in(SRC / "validation.cpp", SIGN_CALL)
        self.assertEqual(
            len(val_hits),
            1,
            f"PersistMatMulExactReplayVerdict must be the only validation.cpp mint: {val_hits}",
        )
        val = (SRC / "validation.cpp").read_text(encoding="utf-8")
        persist_def = val.find("ChainstateManager::PersistMatMulExactReplayVerdict")
        self.assertGreater(persist_def, 0)
        self.assertLess(
            persist_def,
            val.find("SignAuthoritative", persist_def),
            "validation.cpp SignAuthoritative must live in PersistMatMulExactReplayVerdict",
        )
        net_hits = calls_in(SRC / "net_processing.cpp", SIGN_CALL)
        self.assertEqual(
            len(net_hits),
            3,
            f"net_processing SignAuthoritative sites changed: {net_hits}",
        )
        self.assertTrue(
            function_contains(
                SRC / "net_processing.cpp",
                "MaybeRelayLocalExactReplayAttestation",
                "SignAuthoritative",
            ),
            "MaybeRelayLocalExactReplayAttestation must be the ProcessNewBlock mint",
        )
        self.assertTrue(
            function_contains(
                SRC / "net_processing.cpp",
                "MaybeRelayLocalExactReplayAttestation",
                "RelayLocalExactReplayAttestation",
            ),
        )
        rpc_hits = calls_in(SRC / "rpc" / "matmul_trusted.cpp", SIGN_CALL)
        self.assertEqual(
            rpc_hits,
            [464],
            "rpc/matmul_trusted.cpp SignAuthoritative sites changed",
        )

    def test_net_processing_persist_callers_gossip(self) -> None:
        persist = calls_in(SRC / "net_processing.cpp", PERSIST_CALL)
        self.assertEqual(
            len(persist),
            5,
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
            len(persist),
            1,
            f"validation.cpp persist call sites changed: {persist}",
        )
        self.assertFalse(
            window_has_relay(SRC / "validation.cpp", persist[0]),
            "AcceptBlock persist grew a gossip call; validation must not P2P",
        )

    def test_processnewblock_finished_reuses_relay_helper(self) -> None:
        validation = (SRC / "validation.cpp").read_text(encoding="utf-8")
        self.assertIn(
            "ProcessNewBlockFinished(*block)",
            validation,
            "ProcessNewBlock must fire ProcessNewBlockFinished so generate/"
            "submitblock gossip without ProcessBlockSync",
        )
        net = (SRC / "net_processing.cpp").read_text(encoding="utf-8")
        self.assertIn("void PeerManagerImpl::ProcessNewBlockFinished", net)
        self.assertTrue(
            function_contains(
                SRC / "net_processing.cpp",
                "ProcessNewBlockFinished",
                "MaybeRelayLocalExactReplayAttestation",
            ),
        )
        self.assertNotIn(
            "SignAuthoritative",
            net[
                net.find("void PeerManagerImpl::ProcessBlockSync") : net.find(
                    "void PeerManagerImpl::ProcessCompactBlockTxns"
                )
            ],
            "ProcessBlockSync must reuse ProcessNewBlockFinished rather than "
            "a second Sign+Relay path",
        )
        # GETMMATTEST regen / covered-sign both fall through to push_mmattest.
        net_hits = calls_in(SRC / "net_processing.cpp", SIGN_CALL)
        lines = net.splitlines()
        last_getmm = net_hits[-1]
        after = "\n".join(lines[last_getmm - 1 : last_getmm - 1 + 60])
        self.assertIn(
            "push_mmattest",
            after,
            f"GETMMATTEST SignAuthoritative at {last_getmm} lost push_mmattest",
        )
        getmm_chunk = "\n".join(lines[net_hits[1] - 1 : last_getmm + 60])
        self.assertGreaterEqual(
            getmm_chunk.count("SignAuthoritative"),
            2,
            "GETMMATTEST must keep regen and covered-sign mint sites",
        )


if __name__ == "__main__":
    unittest.main()
