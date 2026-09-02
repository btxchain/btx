#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license.
"""
btx_otc — BTX OTC bonded-offer SDK + CLI (proof-of-offered-supply and escrow settlement).

Implements the Phase-1 tooling of doc/btx-otc-escrow-supply-validation.md: an OTC
offer only counts as real supply when it is backed by a *bonded offer vault* — coins
locked in a P2MR output whose only spendable paths are (a) settle this specific offer
and (b) refund to the seller after the offer expires. The offer terms hash is committed
as an unspendable leaf inside the P2MR vault root, so the same outpoint cannot verify
for two different offers and no OP_RETURN data output is required.

The SDK drives a stock btxd via RPC only (no core dependency). Structure mirrors
contrib/wbtx/btx_wbtx.py: pure helpers work offline; anything that touches the chain
takes an `rpc` / `rpc_wallet` callable: rpc(method, *params) -> parsed JSON.

Offer lifecycle::

    from btx_otc import (OfferTerms, soft_bond_descriptor, create_offer, verify_offer)

    # --- Seller: build + fund + publish -------------------------------------
    terms = {
        "version": 1,
        "amount_sats": 5_000_000_000_000,      # 50,000 BTX
        "expiry_height": 812_000,
        "price": "spot-0.5%",                  # free-form; hashed verbatim
        "settle_asset": "wBTX",
        "seller_contact": "otc@desk.example",
        "nonce": os.urandom(16).hex(),         # one offer == one terms hash
    }
    desc = soft_bond_descriptor(settle_pk, terms["expiry_height"], refund_pk)
    bundle = create_offer(rpc, rpc_wallet, terms, desc)   # funds terms-bound vault
    publish(json.dumps(bundle))                            # any channel works

    # --- Buyer / venue: verify against their own node -----------------------
    report = verify_offer(rpc, bundle, min_conf=20)
    assert report.ok, report.failures()

Bond tiers (see the design doc §4.5)::

    A+  ctv_bond_descriptor(...)    no third party; spendable ONLY into the
                                    pre-committed settlement tx, or refund at expiry
    A   venue_bond_descriptor(...)  2-of-2 seller+venue before expiry, refund after;
                                    venue can grief (delay) but never take or redirect
    B   soft_bond_descriptor(...)   seller can settle unilaterally pre-expiry; an
                                    early pull is publicly visible (offer reads dead)

Verification NEVER trusts the seller: descriptor shape is checked against a strict
allow-list (unknown shapes fail closed), outpoints are checked in the UTXO set,
the descriptor's terms-hash commitment is checked against the vault output, and the
optional attestation is checked with verifymessage.

Spend-signing & key-reuse safety (audit guidance):
  * SIGHASH_ALL: every escrow/HTLC spend this SDK helps build must be signed with
    SIGHASH_ALL. A non-ALL sighash (NONE/SINGLE/ANYONECANPAY) leaves the spend's
    outputs malleable by a third party — never sign an escrow spend with anything
    but ALL. (The P2MR script layer permits non-ALL by design; the safety lives
    in HOW you sign.)
  * CSFS key/message uniqueness: OP_CHECKSIGFROMSTACK verifies a signature over a
    witness-supplied message, so a revealed (signature, message/preimage) pair
    REPLAYS on any output that reuses the same key + message. Prefer the
    transaction-bound htlc_tx() leaf (which this SDK uses) over a bare csfs()
    leaf; never reuse a CSFS/oracle key across offers, and bind each CSFS message
    to a unique per-offer context (the terms hash / nonce already provide this).
  * Confirmation depth: treat a bond as real supply only at a reorg-safe depth
    (>= COINBASE_MATURITY here); shallow/RBF-replaceable funding is rejected by
    verify_offer, but off-chain settlement decisions must respect depth too.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable, Optional

Rpc = Callable[..., object]

try:
    hashlib.new("ripemd160", b"")

    def _ripemd160(data: bytes) -> bytes:
        return hashlib.new("ripemd160", data).digest()
except ValueError:
    try:
        from contrib.wbtx._ripemd160 import ripemd160 as _ripemd160
    except ImportError:
        _fallback = Path(__file__).resolve().parents[1] / "wbtx" / "_ripemd160.py"
        spec = importlib.util.spec_from_file_location("btx_wbtx_ripemd160", _fallback)
        if spec is None or spec.loader is None:
            raise ImportError(f"unable to load RIPEMD160 fallback from {_fallback}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _ripemd160 = module.ripemd160

COIN = 100_000_000
COINBASE_MATURITY = 100
RECOMMENDED_MIN_CONF = 20
MAX_VERIFY_OUTPOINTS = 1000
# Funding below this floor is practically unspendable with the default helper
# fee (20_000 sats) once dust and script overhead are accounted for.
MIN_BOND_SATS = 20_000 + 1_000

# Protocol tag used by off-chain attestations and bundle formats. The on-chain
# binding is a hidden P2MR `commit(sha256(terms))` leaf, not an OP_RETURN output.
OTC_TAG = b"BTXOTC1"

# Consensus locktime domain split (BIP65 / CheckLockTime): a CLTV value (and a
# tx nLockTime) BELOW this is a block HEIGHT; AT OR ABOVE it is a Unix TIMESTAMP.
# The whole OTC escrow is height-denominated (terms.expiry_height, the C5
# height<expiry check), and a refund leaf must out-live the offer's expiry
# HEIGHT. A refund_locktime >= this threshold is therefore NOT a "far-future
# height" — it is a timestamp, and any value just above the threshold is a
# timestamp already ~10 years in the past, i.e. a CLTV that is spendable NOW.
# Comparing such a value numerically against a block height (refund_locktime >=
# expiry_height) is a domain confusion that lets a seller advertise an
# "unpullable until expiry" bond whose refund is in fact immediately spendable.
# All escrow/vault locktimes MUST be in the height domain so the numeric
# comparison against expiry_height is meaningful.
LOCKTIME_THRESHOLD = 500_000_000
# Cross-leg HTLC safety margin in BTX blocks. This is materially above the
# observed ~6-block mainnet reorg depth (~30 minutes at ~90-second blocks).
SWAP_REORG_MARGIN_BLOCKS = 20


def require_block_height_locktime(value: int, field: str) -> int:
    """Fail closed unless `value` is a CLTV/nLockTime in the BLOCK-HEIGHT domain
    (0 < value < LOCKTIME_THRESHOLD). Rejects the timestamp domain, which would
    make a height-vs-locktime comparison meaningless and can encode an
    immediately-spendable refund. Returns the value for convenient chaining."""
    if type(value) is not int or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer block height")
    if value <= 0 or value >= LOCKTIME_THRESHOLD:
        raise ValueError(
            f"{field}={value} is not a block-height locktime: it must satisfy "
            f"0 < {field} < {LOCKTIME_THRESHOLD} (LOCKTIME_THRESHOLD). A value "
            f">= the threshold is a Unix-timestamp locktime — comparing it to a "
            f"block height is a domain confusion and can be spendable immediately.")
    return value


# ============================= terms canonicalization =============================

REQUIRED_TERMS_FIELDS = ("version", "amount_sats", "expiry_height", "nonce")


def _no_dup_pairs(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate key in terms JSON: {k!r}")
        seen.add(k)
    return dict(pairs)


def _reject_floats(value, path="terms"):
    """Floats are not allowed anywhere in offer terms — they do not canonicalize."""
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are forbidden in offer terms (use ints/strings)")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: non-string key {k!r}")
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _reject_floats(v, f"{path}[{i}]")


def validate_terms(terms: dict) -> None:
    if not isinstance(terms, dict):
        raise ValueError("terms must be a JSON object")
    _reject_floats(terms)
    for f in REQUIRED_TERMS_FIELDS:
        if f not in terms:
            raise ValueError(f"terms missing required field '{f}'")
    if type(terms["version"]) is not int or terms["version"] != 1:
        raise ValueError("terms.version must be integer 1")
    if type(terms["amount_sats"]) is not int or terms["amount_sats"] <= 0:
        raise ValueError("terms.amount_sats must be a positive integer (satoshis)")
    if terms["amount_sats"] < MIN_BOND_SATS:
        raise ValueError(
            f"terms.amount_sats must be >= {MIN_BOND_SATS} sats to cover "
            "default settlement/refund spend fee and dust margin"
        )
    if type(terms["expiry_height"]) is not int or terms["expiry_height"] <= 0:
        raise ValueError("terms.expiry_height must be a positive integer (block height)")
    # expiry_height is a block height; a value in the timestamp domain would
    # make the refund_locktime >= expiry_height covering check meaningless.
    require_block_height_locktime(terms["expiry_height"], "terms.expiry_height")
    if not isinstance(terms["nonce"], str) or not terms["nonce"]:
        raise ValueError("terms.nonce must be a non-empty string")


def canonical_terms_bytes(terms: dict) -> bytes:
    """Deterministic encoding: JSON with sorted keys, no whitespace, ASCII escapes."""
    validate_terms(terms)
    return json.dumps(terms, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def terms_hash(terms: dict) -> bytes:
    return hashlib.sha256(canonical_terms_bytes(terms)).digest()


def terms_hash_hex(terms: dict) -> str:
    return terms_hash(terms).hex()


def commitment_leaf_expr(terms: dict) -> str:
    """Descriptor leaf that binds a P2MR vault root to exactly these terms."""
    return f"commit({terms_hash_hex(terms)})"


def attestation_message(terms: dict, challenge: str) -> str:
    """The exact string signed/verified for the offer attestation."""
    return f"BTXOTC1|{terms_hash_hex(terms)}|{challenge}"


# ============================= bond descriptors =============================

# A descriptor key expression: raw ML-DSA hex, or pk_slh(<slh-dsa hex>).
_KEY = r"(?:[0-9a-fA-F]+|pk_slh\([0-9a-fA-F]+\))"

_HASH256 = r"[0-9a-fA-F]{64}"
_TIER_B_RE = re.compile(
    rf"^mr\(({_KEY}),\{{refund\((\d+),({_KEY})\),commit\(({_HASH256})\)\}}\)$")
_TIER_A_RE = re.compile(
    rf"^mr\(multi_pq\(2,({_KEY}),({_KEY})\),\{{refund\((\d+),({_KEY})\),commit\(({_HASH256})\)\}}\)$")
_TIER_APLUS_RE = re.compile(
    rf"^mr\(ctv_pk\(({_HASH256}),({_KEY})\),\{{refund\((\d+),({_KEY})\),commit\(({_HASH256})\)\}}\)$")

_TIER_B_UNBOUND_RE = re.compile(
    rf"^mr\(({_KEY}),\{{refund\((\d+),({_KEY})\)\}}\)$")
_TIER_A_UNBOUND_RE = re.compile(
    rf"^mr\(multi_pq\(2,({_KEY}),({_KEY})\),\{{refund\((\d+),({_KEY})\)\}}\)$")
_TIER_APLUS_UNBOUND_RE = re.compile(
    rf"^mr\(ctv_pk\(({_HASH256}),({_KEY})\),\{{refund\((\d+),({_KEY})\)\}}\)$")


def soft_bond_descriptor(settle_pubkey: str, refund_locktime: int, refund_pubkey: str) -> str:
    """Tier B: seller settles unilaterally pre-expiry; refund leaf after expiry."""
    require_block_height_locktime(refund_locktime, "refund_locktime")
    return f"mr({settle_pubkey},{{refund({refund_locktime},{refund_pubkey})}})"


def venue_bond_descriptor(settle_pubkey: str, venue_pubkey: str,
                          refund_locktime: int, refund_pubkey: str) -> str:
    """Tier A: 2-of-2 seller+venue settlement handoff; seller-only refund after expiry."""
    require_block_height_locktime(refund_locktime, "refund_locktime")
    return (f"mr(multi_pq(2,{settle_pubkey},{venue_pubkey}),"
            f"{{refund({refund_locktime},{refund_pubkey})}})")


def ctv_bond_descriptor(ctv_template_hash_hex: str, settle_pubkey: str,
                        refund_locktime: int, refund_pubkey: str) -> str:
    """Tier A+: settlement constrained by covenant to one pre-committed transaction."""
    require_block_height_locktime(refund_locktime, "refund_locktime")
    if (not isinstance(ctv_template_hash_hex, str) or
            not re.fullmatch(_HASH256, ctv_template_hash_hex)):
        raise ValueError("ctv_template_hash_hex must be 32 bytes of hex")
    return (f"mr(ctv_pk({ctv_template_hash_hex.lower()},{settle_pubkey}),"
            f"{{refund({refund_locktime},{refund_pubkey})}})")


@dataclass
class BondInfo:
    tier: str                     # "A+", "A", or "B"
    refund_locktime: int
    refund_pubkey: str
    settle_pubkey: str
    venue_pubkey: Optional[str] = None
    ctv_hash: Optional[str] = None
    commitment_hash: str = ""


def strip_checksum(descriptor: str) -> str:
    return descriptor.split("#", 1)[0]


def parse_bond_descriptor(descriptor: str) -> BondInfo:
    """
    Classify a bond descriptor against the strict allow-list of known shapes.
    Anything else raises — verification MUST fail closed on unknown script trees,
    because an unrecognized leaf could be a hidden early-exit path.
    """
    desc = strip_checksum(descriptor).replace(" ", "")
    m = _TIER_APLUS_RE.match(desc)
    if m:
        return _validated_bond(BondInfo(tier="A+", ctv_hash=m.group(1).lower(), settle_pubkey=m.group(2),
                        refund_locktime=int(m.group(3)), refund_pubkey=m.group(4),
                        commitment_hash=m.group(5).lower()))
    m = _TIER_A_RE.match(desc)
    if m:
        return _validated_bond(BondInfo(tier="A", settle_pubkey=m.group(1), venue_pubkey=m.group(2),
                        refund_locktime=int(m.group(3)), refund_pubkey=m.group(4),
                        commitment_hash=m.group(5).lower()))
    m = _TIER_B_RE.match(desc)
    if m:
        return _validated_bond(BondInfo(tier="B", settle_pubkey=m.group(1),
                        refund_locktime=int(m.group(2)), refund_pubkey=m.group(3),
                        commitment_hash=m.group(4).lower()))
    raise ValueError("unrecognized bond descriptor shape (fail-closed); "
                     "expected a terms-bound tier A+/A/B form")


def _validated_bond(bond: BondInfo) -> BondInfo:
    """Fail closed on a parsed bond whose refund locktime is not a block height.
    A timestamp-domain refund_locktime (>= LOCKTIME_THRESHOLD) would make the
    downstream `refund_locktime >= expiry_height` covering check meaningless and
    can be an immediately-spendable early-exit path — exactly the class of
    hidden early exit parse_bond_descriptor promises to reject."""
    require_block_height_locktime(bond.refund_locktime, "refund_locktime")
    if bond.tier == "A":
        settle_key = (bond.settle_pubkey or "").lower()
        venue_key = (bond.venue_pubkey or "").lower()
        if settle_key == venue_key:
            raise ValueError(
                "tier A descriptor has duplicate multi_pq keys "
                "(settle_pubkey == venue_pubkey): this collapses 2-of-2 to one key"
            )
    return bond


def bind_bond_descriptor(descriptor: str, terms: dict) -> str:
    """Return the tier A+/A/B descriptor with a canonical terms commitment leaf.

    `create_offer` accepts the concise legacy constructor output, but the funded
    descriptor and published bundle are always terms-bound. Already-bound input
    is accepted only when it commits to these exact terms.
    """
    desc = strip_checksum(descriptor).replace(" ", "")
    want = terms_hash_hex(terms)
    try:
        parsed = parse_bond_descriptor(desc)
        if parsed.commitment_hash != want:
            raise ValueError("bond descriptor is committed to different offer terms")
        return desc
    except ValueError as bound_error:
        if "different offer terms" in str(bound_error):
            raise

    m = _TIER_APLUS_UNBOUND_RE.match(desc)
    if m:
        return (f"mr(ctv_pk({m.group(1)},{m.group(2)}),"
                f"{{refund({m.group(3)},{m.group(4)}),commit({want})}})")
    m = _TIER_A_UNBOUND_RE.match(desc)
    if m:
        return (f"mr(multi_pq(2,{m.group(1)},{m.group(2)}),"
                f"{{refund({m.group(3)},{m.group(4)}),commit({want})}})")
    m = _TIER_B_UNBOUND_RE.match(desc)
    if m:
        return (f"mr({m.group(1)},"
                f"{{refund({m.group(2)},{m.group(3)}),commit({want})}})")
    raise ValueError("unrecognized bond descriptor shape (fail-closed); "
                     "expected one of the documented tier A+/A/B forms")


# ============================= node helpers =============================

def add_checksum(rpc: Rpc, descriptor: str) -> str:
    info = rpc("getdescriptorinfo", strip_checksum(descriptor))
    return f"{strip_checksum(descriptor)}#{info['checksum']}"


def bond_address(rpc: Rpc, descriptor_with_checksum: str) -> str:
    addrs = rpc("deriveaddresses", descriptor_with_checksum)
    if len(addrs) != 1:
        raise ValueError("bond descriptor must derive exactly one address")
    return addrs[0]


def refund_key_address(rpc: Rpc, bond: BondInfo) -> str:
    """Derive the single-key P2MR address controlled by a bond's refund key."""
    return bond_address(rpc, add_checksum(rpc, f"mr({bond.refund_pubkey})"))


def ensure_refund_attestation_descriptor(rpc: Rpc, rpc_wallet: Rpc,
                                         bond: BondInfo) -> str:
    """Make the exact refund-key challenge script visible to the signing wallet.

    The private refund key can originate below a different, ranged descriptor.
    Importing this fixed public descriptor lets wallet-wide P2MR signing combine
    that existing private key with the exact single-key script used by verifiers.
    """
    desc_ck = add_checksum(rpc, f"mr({bond.refund_pubkey})")
    address = bond_address(rpc, desc_ck)
    info = rpc_wallet("getaddressinfo", address)
    if not info.get("ismine", False) and not info.get("iswatchonly", False):
        result = rpc_wallet("importdescriptors", [{
            "desc": desc_ck,
            "timestamp": "now",
            "active": False,
            "internal": False,
        }])
        if (not isinstance(result, list) or len(result) != 1 or
                not result[0].get("success", False)):
            detail = result[0].get("error", result) if isinstance(result, list) and result else result
            raise RuntimeError(f"failed to import refund attestation descriptor: {detail}")
    return address


def sats_to_btx_str(sats: int) -> str:
    return f"{sats // COIN}.{sats % COIN:08d}"


def to_sat(amount_btx) -> int:
    """Convert a node decimal-BTX value (str/Decimal) to int satoshis exactly."""
    sats = Decimal(str(amount_btx)).scaleb(8)
    if sats != sats.to_integral_value():
        raise ValueError(f"amount {amount_btx} has sub-satoshi precision")
    return int(sats)


# ============================= offer creation =============================

def create_offer(rpc: Rpc, rpc_wallet: Rpc, terms: dict, descriptor: str,
                 challenge: Optional[str] = None, attest: bool = True,
                 fee_rate: Optional[int] = None) -> dict:
    """
    Fund the bond vault and emit the self-contained offer bundle.

    Builds ONE transaction paying `terms.amount_sats` to a P2MR vault whose Merkle
    root includes `commit(sha256(canonical terms))`. The terms-bound output address
    makes the bond exclusive to this offer without a data-carrier output.

    If `attest` is set, the bundle also carries a BIP-322 attestation: a fresh
    challenge signed (signmessage) with the wallet address that owns the refund
    key, proving the offer publisher controls the bond's exit key.
    """
    validate_terms(terms)
    descriptor = bind_bond_descriptor(descriptor, terms)
    bond = parse_bond_descriptor(descriptor)
    if bond.refund_locktime < terms["expiry_height"]:
        raise ValueError("refund locktime is below terms.expiry_height: the seller "
                         "could exit before the offer expires")
    if (bond.tier == "A+" and
            str(terms.get("ctv_template_hash", "")).lower() != bond.ctv_hash):
        raise ValueError("tier A+ terms.ctv_template_hash must equal the descriptor's "
                         "pre-committed settlement template hash")

    desc_ck = add_checksum(rpc, descriptor)
    address = bond_address(rpc, desc_ck)

    # Complete all validation and signing before broadcasting the funding
    # transaction. A bad attestation request must never strand coins in a vault
    # while create_offer exits without returning its bundle.
    attestation = None
    if attest:
        challenge = challenge or os.urandom(16).hex()
        attest_addr = terms.get("seller_address")
        if not attest_addr:
            raise ValueError("attest=True requires terms.seller_address (the P2MR "
                             "address controlled by the refund key); pass "
                             "attest=False to skip")
        expected_addr = refund_key_address(rpc, bond)
        if attest_addr != expected_addr:
            raise ValueError("terms.seller_address is not the P2MR address controlled "
                             "by the bond refund key")
        imported_addr = ensure_refund_attestation_descriptor(rpc, rpc_wallet, bond)
        if imported_addr != expected_addr:
            raise RuntimeError("refund attestation descriptor derived an unexpected address")
        sig = rpc_wallet("signmessage", attest_addr, attestation_message(terms, challenge))
        attestation = {"address": attest_addr, "challenge": challenge,
                       "signature": sig}

    outputs = [{address: sats_to_btx_str(terms["amount_sats"])}]
    options = {}
    if fee_rate is not None:
        options["fee_rate"] = fee_rate
    res = rpc_wallet("send", outputs, None, "unset", None, options)
    if not res.get("complete", False):
        raise RuntimeError("wallet send did not complete (locked wallet / insufficient funds?)")
    txid = res["txid"]

    # Locate the vault vout in the funding tx.
    raw = rpc_wallet("gettransaction", txid)
    decoded = rpc("decoderawtransaction", raw["hex"])
    vout = None
    for out in decoded["vout"]:
        spk = out.get("scriptPubKey", {})
        if spk.get("address") == address:
            vout = out["n"]
            break
    if vout is None:
        raise RuntimeError("funding tx does not pay the bond address (unexpected)")

    bundle = {
        "version": 1,
        "terms": terms,
        "bond": {
            "descriptor": desc_ck,
            "tier": bond.tier,
            "outpoints": [{"txid": txid, "vout": vout}],
        },
    }

    if attestation is not None:
        bundle["attestation"] = attestation
    return bundle


# ============================= offer verification =============================

@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class OfferVerification:
    ok: bool
    tier: str
    address: str
    verified_sats: int
    expiry_height: int
    checks: list = field(default_factory=list)

    def failures(self) -> list:
        return [c for c in self.checks if not c.ok]

    def as_dict(self) -> dict:
        return {
            "ok": self.ok, "tier": self.tier, "address": self.address,
            "verified_sats": self.verified_sats, "expiry_height": self.expiry_height,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
        }


def verify_offer(rpc: Rpc, bundle: dict, min_conf: int = RECOMMENDED_MIN_CONF,
                 require_attestation: bool = False,
                 expected_challenge: Optional[str] = None,
                 expected_venue_pubkey: Optional[str] = None,
                 expected_ctv_template_hash: Optional[str] = None) -> OfferVerification:
    """
    Run the full §4.3 verification against a local node. Returns a report whose
    `ok` is True only if every executed check passed. Trust-minimized: nothing is
    accepted from the bundle without being re-checked on-chain, and unknown
    descriptor shapes fail closed.
    """
    checks: list = []
    tier, address, verified_sats, expiry = "?", "", 0, 0

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append(Check(name, bool(ok), detail))
        return bool(ok)

    if not isinstance(bundle, dict):
        check("bundle", False, "bundle must be a JSON object")
        return OfferVerification(False, tier, address, 0, 0, checks)

    if type(min_conf) is not int or min_conf < 0:
        check("parameters", False, "min_conf must be a non-negative integer")
        return OfferVerification(False, tier, address, 0, 0, checks)
    if min_conf < RECOMMENDED_MIN_CONF:
        check(
            "min-conf-advisory",
            True,
            f"min_conf={min_conf} is below the recommended reorg-safe depth "
            f"({RECOMMENDED_MIN_CONF})",
        )
    if (expected_challenge is not None and
            (not isinstance(expected_challenge, str) or not expected_challenge)):
        check("parameters", False, "expected_challenge must be a non-empty string")
        return OfferVerification(False, tier, address, 0, 0, checks)
    if (expected_venue_pubkey is not None and
            (not isinstance(expected_venue_pubkey, str) or not expected_venue_pubkey)):
        check("parameters", False, "expected_venue_pubkey must be a non-empty string")
        return OfferVerification(False, tier, address, 0, 0, checks)
    if (expected_ctv_template_hash is not None and
            (not isinstance(expected_ctv_template_hash, str) or
             not re.fullmatch(_HASH256, expected_ctv_template_hash))):
        check("parameters", False,
              "expected_ctv_template_hash must be a non-empty 32-byte hex string")
        return OfferVerification(False, tier, address, 0, 0, checks)

    # C1 — terms are well-formed and canonicalizable.
    terms = bundle.get("terms")
    try:
        if type(bundle.get("version")) is not int or bundle.get("version") != 1:
            raise ValueError("bundle.version must be integer 1")
        want_commitment = terms_hash_hex(terms)
        expiry = terms["expiry_height"]
        check("terms-canonical", True, f"terms_hash={terms_hash_hex(terms)}")
    except Exception as e:  # noqa: BLE001
        check("terms-canonical", False, str(e))
        return OfferVerification(False, tier, address, 0, 0, checks)

    # C2 — descriptor parses, is a known bond shape, and its timelock covers expiry.
    expected_attest_address = ""
    try:
        bond_bundle = bundle["bond"]
        if not isinstance(bond_bundle, dict):
            raise ValueError("bundle.bond must be a JSON object")
        desc = bond_bundle["descriptor"]
        if not isinstance(desc, str):
            raise ValueError("bond.descriptor must be a string")
        desc_body, has_checksum, supplied_checksum = desc.partition("#")
        descriptor_info = rpc("getdescriptorinfo", desc_body)
        if has_checksum and supplied_checksum != descriptor_info["checksum"]:
            raise ValueError("bond descriptor checksum does not match its descriptor")
        desc_ck = f"{desc_body}#{descriptor_info['checksum']}"
        address = bond_address(rpc, desc_ck)
        bond = parse_bond_descriptor(desc)
        tier = bond.tier
        if bond_bundle.get("tier") != tier:
            raise ValueError(
                f"bond.tier {bond_bundle.get('tier')!r} does not match derived tier {tier!r}"
            )
        expected_attest_address = refund_key_address(rpc, bond)
        check("commitment", bond.commitment_hash == want_commitment,
              f"descriptor commits {bond.commitment_hash}; expected {want_commitment}")
        ctv_terms_ok = (bond.tier != "A+" or
                        str(terms.get("ctv_template_hash", "")).lower() == bond.ctv_hash)
        ok = bond.refund_locktime >= expiry and ctv_terms_ok
        check("descriptor-shape", ok,
              f"tier={bond.tier} refund_locktime={bond.refund_locktime} expiry={expiry}"
              + ("" if bond.tier != "A+" else
                 f" ctv_template_hash={bond.ctv_hash} terms_match={ctv_terms_ok}")
              + ("" if bond.refund_locktime >= expiry else
                 " (refund unlocks BEFORE offer expiry)"))
        # Tier A's "the venue can grief but never take" guarantee holds ONLY if
        # the 2-of-2 venue key is an independent party the buyer trusts. Nothing
        # on-chain proves that: a seller can set venue_pubkey to a second key it
        # controls, making the settlement path unilaterally seller-signable so
        # the seller pulls the bond mid-quote (phantom supply). The buyer must
        # PIN the venue key. Fail closed for tier A unless it is pinned and matches.
        if bond.tier == "A":
            if expected_venue_pubkey is None:
                check("venue-key", False,
                      f"tier A bond requires expected_venue_pubkey to prove the venue "
                      f"is an independent party (descriptor venue_pubkey={bond.venue_pubkey}); "
                      f"without it the 2-of-2 could be seller+seller and pullable mid-quote")
            else:
                venue_ok = (bond.venue_pubkey or "").lower() == expected_venue_pubkey.lower()
                check("venue-key", venue_ok,
                      f"descriptor venue_pubkey={bond.venue_pubkey}; "
                      f"expected={expected_venue_pubkey}")
        elif expected_venue_pubkey is not None:
            check("venue-key", False,
                  f"expected_venue_pubkey pins tier A but bond is tier {bond.tier}")
        if bond.tier == "A+":
            if expected_ctv_template_hash is None:
                check("ctv-template", False,
                      "tier A+ requires expected_ctv_template_hash (independently "
                      "derived by the buyer from the agreed settlement outputs) to "
                      "prove the covenant pays the buyer; the descriptor+terms hash "
                      "is seller-supplied")
            else:
                ctv_ok = bond.ctv_hash.lower() == expected_ctv_template_hash.lower()
                check("ctv-template", ctv_ok,
                      f"descriptor ctv_template_hash={bond.ctv_hash}; "
                      f"expected={expected_ctv_template_hash}")
        elif expected_ctv_template_hash is not None:
            check("ctv-template", False,
                  f"expected_ctv_template_hash pins tier A+ but bond is tier {bond.tier}")
    except Exception as e:  # noqa: BLE001
        check("descriptor-shape", False, str(e))
        return OfferVerification(False, tier, address, 0, expiry, checks)

    # C3 — outpoints exist, are unspent, pay the vault, and are confirmed.
    outpoints = bundle["bond"].get("outpoints", [])
    if not isinstance(outpoints, list):
        check("outpoints", False, "bond.outpoints must be a JSON array")
        return OfferVerification(False, tier, address, 0, expiry, checks)
    if len(outpoints) > MAX_VERIFY_OUTPOINTS:
        check(
            "outpoints",
            False,
            f"bond.outpoints has {len(outpoints)} entries; max allowed is {MAX_VERIFY_OUTPOINTS}",
        )
        return OfferVerification(False, tier, address, 0, expiry, checks)
    seen = set()
    all_utxos_ok = len(outpoints) > 0
    if not outpoints:
        check("outpoints", False, "bundle lists no outpoints")
    for op in outpoints:
        if (not isinstance(op, dict) or
                not isinstance(op.get("txid"), str) or
                not re.fullmatch(_HASH256, op["txid"]) or
                type(op.get("vout")) is not int or op["vout"] < 0):
            all_utxos_ok = check(
                "outpoints", False,
                f"malformed outpoint {op!r}; expected 32-byte hex txid and non-negative integer vout",
            ) and all_utxos_ok
            continue
        key = (op["txid"].lower(), op["vout"])
        if key in seen:
            all_utxos_ok = check("outpoints", False, f"duplicate outpoint {key}") and all_utxos_ok
            continue
        seen.add(key)
        try:
            # Include the mempool so a bond already consumed by an unconfirmed
            # settlement/refund cannot continue to verify as offered supply.
            utxo = rpc("gettxout", op["txid"], op["vout"], True)
        except Exception as e:  # noqa: BLE001
            all_utxos_ok = check(
                "outpoints", False,
                f"gettxout failed for {op['txid']}:{op['vout']}: {e}",
            ) and all_utxos_ok
            continue
        if utxo is None:
            all_utxos_ok = check("outpoints", False,
                                 f"{op['txid']}:{op['vout']} not in UTXO set "
                                 "(spent, unconfirmed, or fabricated)") and all_utxos_ok
            continue
        spk_addr = utxo.get("scriptPubKey", {}).get("address")
        if spk_addr != address:
            all_utxos_ok = check("outpoints", False,
                                 f"{op['txid']}:{op['vout']} pays {spk_addr}, "
                                 f"not the bond vault {address}") and all_utxos_ok
            continue
        confs = int(utxo.get("confirmations", 0))
        # RBF only matters while the funding is UNCONFIRMED (it can then be
        # fee-bump-replaced away after the buyer acts — the real T5 danger). Once
        # confirmed, BIP125 signaling is moot (a mined tx cannot be replaced; only
        # a reorg could undo it, which the confirmation-depth / min-conf-advisory
        # checks cover). So only inspect the raw tx for a 0-conf outpoint — and a
        # 0-conf tx is in the mempool, where getrawtransaction works WITHOUT
        # -txindex, preserving the SDK's stock-node ("no txindex needed") promise.
        if confs == 0:
            rbf_note = ""
            try:
                tx_verbose = rpc("getrawtransaction", op["txid"], True)
                if not isinstance(tx_verbose, dict):
                    raise ValueError("getrawtransaction did not return a JSON object")
                vin = tx_verbose.get("vin")
                if not isinstance(vin, list):
                    raise ValueError("getrawtransaction response has no vin array")
                for i, txin in enumerate(vin):
                    if not isinstance(txin, dict):
                        raise ValueError(f"vin[{i}] is not a JSON object")
                    sequence = txin.get("sequence")
                    if type(sequence) is not int:
                        raise ValueError(f"vin[{i}].sequence is missing or not an integer")
                    if sequence < 0xFFFFFFFE:
                        rbf_note = " and signals BIP125 replaceability"
                        break
            except Exception as e:  # noqa: BLE001
                rbf_note = f" (BIP125 status undetermined: {e})"
            all_utxos_ok = check(
                "rbf-replaceable", False,
                f"{op['txid']}:{op['vout']} is unconfirmed (0 conf){rbf_note}",
            ) and all_utxos_ok
            continue
        # Confirmed: RBF is moot; do not fetch the raw tx (would need -txindex) and
        # do not reject on the RBF flag (Core wallets signal RBF by default).
        all_utxos_ok = check(
            "rbf-replaceable", True,
            f"{op['txid']}:{op['vout']} is confirmed (RBF moot post-confirmation)",
        ) and all_utxos_ok
        if confs < min_conf:
            all_utxos_ok = check("outpoints", False,
                                 f"{op['txid']}:{op['vout']} has {confs} confirmations "
                                 f"(< {min_conf})") and all_utxos_ok
            continue
        if utxo.get("coinbase", False) and confs < COINBASE_MATURITY:
            all_utxos_ok = check(
                "outpoints", False,
                f"{op['txid']}:{op['vout']} is an immature coinbase with {confs} "
                f"confirmations (< {COINBASE_MATURITY})",
            ) and all_utxos_ok
            continue
        verified_sats += to_sat(utxo["value"])
        check("outpoints", True, f"{op['txid']}:{op['vout']} {utxo['value']} BTX, {confs} conf")

    amount_ok = verified_sats >= terms["amount_sats"]
    check("amount", amount_ok,
          f"verified {verified_sats} sats vs terms.amount_sats {terms['amount_sats']}")
    all_utxos_ok = all_utxos_ok and amount_ok

    # C5 — offer not already expired.
    height = rpc("getblockcount")
    not_expired = height < expiry
    check("not-expired", not_expired, f"height={height} expiry={expiry}")

    # C6 — optional freshness / publisher-controls-refund-key attestation.
    # The signer address must be both committed in the terms and derived from
    # the descriptor's refund key; accepting an arbitrary bundle-supplied
    # address would prove no relationship to the bonded coins.
    att = bundle.get("attestation")
    att_ok = True
    if att:
        try:
            msg = attestation_message(terms, att["challenge"])
            address_bound = (att["address"] == terms.get("seller_address") ==
                             expected_attest_address)
            challenge_bound = (expected_challenge is None or
                               att["challenge"] == expected_challenge)
            signature_ok = bool(rpc("verifymessage", att["address"], att["signature"], msg))
            att_ok = address_bound and challenge_bound and signature_ok
            check("attestation", att_ok,
                  f"address={att['address']} refund_address={expected_attest_address} "
                  f"address_bound={address_bound} challenge_bound={challenge_bound} "
                  f"signature_valid={signature_ok}")
        except Exception as e:  # noqa: BLE001
            att_ok = check("attestation", False, str(e))
    elif require_attestation:
        att_ok = check("attestation", False, "bundle carries no attestation")

    ok = all(c.ok for c in checks)
    return OfferVerification(ok, tier, address, verified_sats, expiry, checks)


def watch_offer(rpc: Rpc, bundle: dict, interval: float = 30.0,
                on_event: Optional[Callable[[str, dict], None]] = None) -> str:
    """
    Poll the bond outpoints until the offer terminates. Returns one of:
    "spent" (a bond outpoint left the UTXO set before expiry — settlement or,
    for tier B, a pull; either way the offer is no longer backed), or
    "expired" (chain passed terms.expiry_height).
    """
    terms = bundle["terms"]
    outpoints = bundle["bond"]["outpoints"]

    def emit(kind: str, data: dict):
        if on_event:
            on_event(kind, data)

    while True:
        height = rpc("getblockcount")
        # Spent-ness wins over expiry: it is the terminal fact about the coins.
        for op in outpoints:
            # Mempool spends terminate the offer immediately; waiting for the
            # spend to confirm creates a double-quote window.
            if rpc("gettxout", op["txid"], op["vout"], True) is None:
                emit("spent", {"outpoint": op, "height": height})
                return "spent"
        if height >= terms["expiry_height"]:
            emit("expired", {"height": height})
            return "expired"
        emit("tick", {"height": height})
        time.sleep(interval)


# ============================= settlement (stage 2) =============================

def _is_unknown_method(exc: Exception) -> bool:
    err = getattr(exc, "error", None)
    code = err.get("code") if isinstance(err, dict) else getattr(exc, "code", None)
    if code == -32601:
        return True
    msg = str(exc).lower()
    return "method not found" in msg or "unknown command" in msg


def build_bond_refund(rpc_wallet: Rpc, descriptor_with_checksum: str, txid: str,
                      vout: int, dest_address: str, locktime: int,
                      fee_sat: int = 20000) -> str:
    """
    Reclaim an expired bond via its refund(locktime, key) leaf. Reuses the node's
    buildhtlcrefund RPC, which accepts any mr() descriptor containing a refund
    leaf and signs with the wallet-held sender key. Returns signed raw tx hex.
    """
    try:
        res = rpc_wallet("buildhtlcrefund", descriptor_with_checksum,
                         {"txid": txid, "vout": vout}, dest_address, locktime, fee_sat,
                         True)
    except Exception as e:  # noqa: BLE001
        if _is_unknown_method(e):
            raise NotImplementedError(
                "buildhtlcrefund RPC unavailable on this node; upgrade to a btxd "
                "with the HTLC bridging RPCs") from e
        raise
    if not res.get("complete", False):
        raise RuntimeError("bond refund did not sign completely; check the locktime "
                           "has been reached and the wallet owns the refund key")
    return res["hex"]


def check_swap_timeout_asymmetry(btx_refund_height: int, other_leg_deadline_height: int,
                                 reorg_margin_blocks: int = SWAP_REORG_MARGIN_BLOCKS) -> None:
    """Fail closed unless the BTX refund is safely LATER than the other leg deadline:
    other_leg_deadline_height + reorg_margin_blocks < btx_refund_height. Both
    values are BTX block heights (convert an EVM unix timeout first, e.g.
    current_height + (evm_timeout_unix - now_unix)//block_seconds). This prevents
    claim-one-leg/refund-the-other theft and leaves reorg/censorship margin after
    a preimage-revealing claim.

    NECESSARY BUT NOT SUFFICIENT: callers MUST also enforce the safe Model-B
    assignment before funding:
      - preimage-holder FUNDS the BTX/long leg, and
      - preimage-holder CLAIMS the shorter/other leg first (the one that expires first).
    If the preimage-holder instead claims the BTX/long leg, this inequality alone
    does not prevent claim-one-leg/refund-the-other theft."""
    require_block_height_locktime(btx_refund_height, "btx_refund_height")
    require_block_height_locktime(other_leg_deadline_height, "other_leg_deadline_height")
    if (type(reorg_margin_blocks) is not int or isinstance(reorg_margin_blocks, bool) or
            reorg_margin_blocks < 1):
        raise ValueError("reorg_margin_blocks must be an integer >= 1")
    if other_leg_deadline_height + reorg_margin_blocks >= btx_refund_height:
        required_min = other_leg_deadline_height + reorg_margin_blocks + 1
        raise ValueError(
            "unsafe cross-leg timeout asymmetry: requires "
            "other_leg_deadline_height + reorg_margin_blocks < btx_refund_height; "
            f"got btx_refund_height={btx_refund_height}, "
            f"other_leg_deadline_height={other_leg_deadline_height}, "
            f"reorg_margin_blocks={reorg_margin_blocks}. "
            f"Need btx_refund_height >= {required_min}.")


def swap_vault_descriptor(preimage_hash160_hex: str, claimer_pubkey: str, refund_locktime: int,
                          sender_pubkey: str) -> str:
    """Stage-2, two-leaf HTLC settlement vault (identical to the wBTX Model-B leg).

    Before funding: validate HTLC refund-leaf timeout asymmetry with
    check_swap_timeout_asymmetry(...) AND ensure preimage assignment follows the
    safe flow (preimage-holder funds BTX/long leg and claims shorter/other leg first).
    """
    # Same domain rule as the bond refund: the HTLC refund leaf's locktime must
    # be a block height so its relation to the offer/expiry is meaningful and it
    # is not immediately spendable as a past timestamp.
    require_block_height_locktime(refund_locktime, "refund_locktime")
    return (f"mr(htlc_tx({preimage_hash160_hex},{claimer_pubkey}),"
            f"refund({refund_locktime},{sender_pubkey}))")


def new_preimage() -> bytes:
    return os.urandom(32)


def swap_hash160_hex(preimage: bytes) -> str:
    """RIPEMD160(SHA256(preimage)) — same hashlock domain as the EVM HTLC contract."""
    return _ripemd160(hashlib.sha256(preimage).digest()).hex()


def build_swap_claim(rpc_wallet: Rpc, descriptor_with_checksum: str, txid: str,
                     vout: int, preimage: bytes, dest_address: str,
                     fee_sat: int = 20000) -> str:
    """Build+sign the preimage-revealing claim tx (via buildhtlcclaim) and return hex; does not broadcast.

    WARNING: broadcasting reveals the preimage on-chain. Confirm the HTLC funding
    output is deeply confirmed and not RBF-replaceable before broadcasting; revealing
    against unconfirmed or replaceable funding lets the counterparty replace that
    funding and reuse the now-public preimage to take the other (cross-chain) leg.
    The integrator MUST also validate cross-leg timeout asymmetry with
    check_swap_timeout_asymmetry(...) before funding, and MUST keep the safe flow:
    preimage-holder funds the BTX/long leg and claims the shorter/other leg first.
    Timeout ordering without that preimage-role assignment is insufficient, per
    doc §5 and WBTXAtomicSwapHTLC.sol.
    """
    try:
        res = rpc_wallet("buildhtlcclaim", descriptor_with_checksum,
                         {"txid": txid, "vout": vout}, preimage.hex(),
                         dest_address, fee_sat)
    except Exception as e:  # noqa: BLE001
        if _is_unknown_method(e):
            raise NotImplementedError(
                "buildhtlcclaim RPC unavailable on this node; upgrade to a btxd "
                "with the HTLC bridging RPCs") from e
        raise
    if not res.get("complete", False):
        raise RuntimeError("swap claim did not sign completely; check the preimage "
                           "and that the wallet owns the claimer key")
    return res["hex"]


def build_swap_refund(rpc_wallet: Rpc, descriptor_with_checksum: str, txid: str,
                      vout: int, dest_address: str, locktime: int,
                      fee_sat: int = 20000) -> str:
    """Seller reclaims an unclaimed settlement vault after its timeout."""
    res = rpc_wallet("buildhtlcrefund", descriptor_with_checksum,
                     {"txid": txid, "vout": vout}, dest_address, locktime, fee_sat)
    if not res.get("complete", False):
        raise RuntimeError("swap refund did not sign completely; check the locktime "
                           "has been reached and the wallet owns the sender key")
    return res["hex"]


# ============================= offline selftest =============================

def selftest() -> None:
    """Offline sanity of the pure helpers (no node needed). Raises on failure."""
    terms = {"version": 1, "amount_sats": MIN_BOND_SATS, "expiry_height": 100,
             "nonce": "00" * 16, "b": [1, {"a": "x"}]}
    # Canonicalization is order-insensitive and whitespace-free.
    reordered = json.loads(json.dumps(terms)[::-1][::-1], object_pairs_hook=_no_dup_pairs)
    assert terms_hash(terms) == terms_hash(dict(reversed(list(reordered.items()))))
    assert canonical_terms_bytes(terms) == canonical_terms_bytes(reordered)
    # Duplicate JSON keys are rejected at parse boundaries.
    try:
        json.loads('{"a":1,"a":2}', object_pairs_hook=_no_dup_pairs)
        raise AssertionError("duplicate object keys must be rejected")
    except ValueError:
        pass
    # Floats are rejected.
    try:
        terms_hash({"version": 1, "amount_sats": MIN_BOND_SATS, "expiry_height": 1,
                    "nonce": "00", "price": 1.5})
        raise AssertionError("float in terms must be rejected")
    except ValueError:
        pass
    # Bond amount floor rejects permanently unclaimable dust-level offers.
    try:
        validate_terms({"version": 1, "amount_sats": 1, "expiry_height": 1, "nonce": "x"})
        raise AssertionError("sub-floor amount_sats must be rejected")
    except ValueError:
        pass
    validate_terms({"version": 1, "amount_sats": MIN_BOND_SATS, "expiry_height": 1, "nonce": "x"})
    assert commitment_leaf_expr(terms) == f"commit({terms_hash_hex(terms)})"
    # Descriptor round-trips for all tiers. create_offer performs this binding
    # automatically before funding; the pure helper is pinned here.
    k1, k2, k3 = "aa" * 1312, "bb" * 1312, "cc" * 1312
    b_desc = bind_bond_descriptor(soft_bond_descriptor(k1, 900, k2), terms)
    b = parse_bond_descriptor(b_desc)
    assert (b.tier, b.refund_locktime, b.settle_pubkey, b.refund_pubkey) == ("B", 900, k1, k2)
    a_desc = bind_bond_descriptor(venue_bond_descriptor(k1, k3, 901, k2), terms)
    a = parse_bond_descriptor(a_desc)
    assert (a.tier, a.venue_pubkey, a.refund_locktime) == ("A", k3, 901)
    # Tier A duplicate multi_pq keys are rejected (must remain independent 2-of-2).
    try:
        parse_bond_descriptor(bind_bond_descriptor(venue_bond_descriptor(k1, k1, 901, k2), terms))
        raise AssertionError("tier A duplicate settle/venue keys must be rejected")
    except ValueError:
        pass
    ap_desc = bind_bond_descriptor(ctv_bond_descriptor("11" * 32, k1, 902, k2), terms)
    ap = parse_bond_descriptor(ap_desc)
    assert f"ctv_pk({'11' * 32},{k1})" in ap_desc
    assert (ap.tier, ap.ctv_hash, ap.refund_locktime) == ("A+", "11" * 32, 902)
    assert b.commitment_hash == a.commitment_hash == ap.commitment_hash == terms_hash_hex(terms)
    # SLH-DSA key forms parse too.
    parse_bond_descriptor(bind_bond_descriptor(
        soft_bond_descriptor(f"pk_slh({'dd' * 32})", 900, k2), terms))
    # Unknown shapes fail closed.
    for bad in (f"mr({k1})",                                             # no refund leaf
                f"mr({k1},{{htlc_tx({'ee' * 20},{k2}),refund(900,{k2})}})",  # extra leaf
                f"mr(multi_pq(1,{k1},{k3}),{{refund(900,{k2})}})"):       # 1-of-2 settle
        try:
            bind_bond_descriptor(bad, terms)
            raise AssertionError(f"must fail closed: {bad[:40]}...")
        except ValueError:
            pass
    # Locktime domain guard: a refund_locktime in the TIMESTAMP domain
    # (>= LOCKTIME_THRESHOLD) is a hidden immediately-spendable early exit and
    # MUST fail closed everywhere — parse, build, and terms validation.
    ts = LOCKTIME_THRESHOLD              # first timestamp-domain value
    ts_lock = LOCKTIME_THRESHOLD + 1     # a timestamp ~10 years in the past
    # Builders reject it.
    for build in (
        lambda: soft_bond_descriptor(k1, ts_lock, k2),
        lambda: venue_bond_descriptor(k1, k3, ts_lock, k2),
        lambda: ctv_bond_descriptor("11" * 32, k1, ts_lock, k2),
        lambda: swap_vault_descriptor("ab" * 20, k1, ts_lock, k2),
    ):
        try:
            build()
            raise AssertionError("timestamp-domain refund_locktime must be rejected at build")
        except ValueError:
            pass
    # The verifier's fail-closed parser rejects a hand-crafted timestamp-domain
    # bond even though it is numerically >= a (height) expiry.
    evil_terms = {"version": 1, "amount_sats": MIN_BOND_SATS, "expiry_height": 100, "nonce": "00" * 16}
    evil_desc = bind_bond_descriptor(f"mr({k1},{{refund({ts_lock},{k2})}})", evil_terms)
    try:
        parse_bond_descriptor(evil_desc)
        raise AssertionError("parse_bond_descriptor must reject a timestamp-domain refund locktime")
    except ValueError:
        pass
    assert ts_lock >= evil_terms["expiry_height"]  # the confusion the numeric check missed
    # A height-domain bond at exactly the threshold-minus-one still parses.
    ok_desc = bind_bond_descriptor(f"mr({k1},{{refund({ts - 1},{k2})}})", evil_terms)
    assert parse_bond_descriptor(ok_desc).refund_locktime == ts - 1
    # terms.expiry_height in the timestamp domain is rejected.
    try:
        validate_terms({"version": 1, "amount_sats": MIN_BOND_SATS, "expiry_height": ts, "nonce": "x"})
        raise AssertionError("timestamp-domain expiry_height must be rejected")
    except ValueError:
        pass

    # Tier-A venue-key pinning: an empty expected_venue_pubkey is rejected in the
    # offline parameter-validation stage (no node touched before it).
    vrep = verify_offer(None, {"version": 1, "terms": {}}, expected_venue_pubkey="")
    assert any(c.name == "parameters" and not c.ok for c in vrep.checks)
    # Tier-A+ CTV pinning: an empty expected_ctv_template_hash is rejected in the
    # same offline parameter-validation stage (no node touched before it).
    vrep = verify_offer(None, {"version": 1, "terms": {}}, expected_ctv_template_hash="")
    assert any(c.name == "parameters" and not c.ok for c in vrep.checks)
    # Pinned tier requirements fail closed when the descriptor is another tier.
    tier_terms = {"version": 1, "amount_sats": MIN_BOND_SATS, "expiry_height": 100, "nonce": "11" * 16}
    tier_b_desc = bind_bond_descriptor(soft_bond_descriptor(k1, 900, k2), tier_terms)

    def _tier_selftest_rpc(method: str, *params):
        if method == "getdescriptorinfo":
            desc = params[0]
            return {"checksum": hashlib.sha256(str(desc).encode("ascii")).hexdigest()[:8]}
        if method == "deriveaddresses":
            desc_ck = params[0]
            return [f"btx_test_{hashlib.sha256(str(desc_ck).encode('ascii')).hexdigest()[:16]}"]
        if method == "getblockcount":
            return 1
        raise AssertionError(f"unexpected rpc call in selftest: {method} {params!r}")

    tier_bundle = {
        "version": 1,
        "terms": tier_terms,
        "bond": {"descriptor": tier_b_desc, "tier": "B", "outpoints": []},
    }
    vrep = verify_offer(_tier_selftest_rpc, tier_bundle, expected_venue_pubkey=k3)
    assert any(c.name == "venue-key" and not c.ok and
               "pins tier A but bond is tier B" in c.detail for c in vrep.checks)
    vrep = verify_offer(_tier_selftest_rpc, tier_bundle, expected_ctv_template_hash="22" * 32)
    assert any(c.name == "ctv-template" and not c.ok and
               "pins tier A+ but bond is tier B" in c.detail for c in vrep.checks)
    # Outpoint bundles above the hard cap are rejected before per-outpoint RPC churn.
    oversized_bundle = {
        "version": 1,
        "terms": tier_terms,
        "bond": {
            "descriptor": tier_b_desc,
            "tier": "B",
            "outpoints": [{"txid": "11" * 32, "vout": i} for i in range(MAX_VERIFY_OUTPOINTS + 1)],
        },
    }
    vrep = verify_offer(_tier_selftest_rpc, oversized_bundle)
    assert any(c.name == "outpoints" and not c.ok and
               "max allowed" in c.detail for c in vrep.checks)

    # Cross-leg timeout asymmetry helper: other+margin must be STRICTLY below BTX.
    check_swap_timeout_asymmetry(btx_refund_height=1000, other_leg_deadline_height=900)
    check_swap_timeout_asymmetry(btx_refund_height=921, other_leg_deadline_height=900)
    try:
        check_swap_timeout_asymmetry(btx_refund_height=920, other_leg_deadline_height=900)
        raise AssertionError("boundary case must fail: other+margin must be strictly lower")
    except ValueError:
        pass
    try:
        check_swap_timeout_asymmetry(btx_refund_height=910, other_leg_deadline_height=900)
        raise AssertionError("too-tight timeout asymmetry must fail closed")
    except ValueError:
        pass
    # swap_hash160 fallback path uses same test vector as wBTX helper.
    assert swap_hash160_hex(bytes([0x42]) * 32) == "8739f40ec4dbf569dcb38134c6e7310908566981"

    # Amount formatting.
    assert sats_to_btx_str(5_000_000_000_000) == "50000.00000000"
    assert to_sat("50000.00000000") == 5_000_000_000_000
    assert to_sat(Decimal("0.00000001")) == 1
    print("btx_otc selftest: OK")


# ============================= CLI =============================

def _make_cli_rpc(cli_cmd: str) -> Rpc:
    """rpc(method, *params) by shelling out to btx-cli (handles auth/cookie for us)."""
    base = shlex.split(cli_cmd)

    def rpc(method: str, *params):
        argv = list(base) + [method]
        for p in params:
            if isinstance(p, str):
                argv.append(p)
            else:
                argv.append(json.dumps(p))
        out = subprocess.run(argv, capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"{method} failed: {out.stderr.strip() or out.stdout.strip()}")
        text = out.stdout.strip()
        if not text:
            return None
        try:
            return json.loads(text, object_pairs_hook=_no_dup_pairs)
        except json.JSONDecodeError:
            return text  # bare-string results (e.g. signmessage)
    return rpc


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=_no_dup_pairs)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="btx_otc", description=__doc__.splitlines()[1])
    p.add_argument("--cli", default="btx-cli",
                   help="node CLI command incl. flags, e.g. "
                        "'btx-cli -regtest -rpcwallet=desk' (default: btx-cli)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("hash-terms", help="print the canonical terms hash of a terms JSON file")
    sp.add_argument("terms_json")

    sp = sub.add_parser("create", help="fund a bond vault and print the offer bundle")
    sp.add_argument("terms_json")
    sp.add_argument("descriptor", help="bond descriptor (tier A+/A/B shape)")
    sp.add_argument("--no-attest", action="store_true")
    sp.add_argument("--challenge", default=None)

    sp = sub.add_parser("verify", help="verify an offer bundle against the node")
    sp.add_argument("bundle_json")
    sp.add_argument("--min-conf", type=int, default=RECOMMENDED_MIN_CONF)
    sp.add_argument("--require-attestation", action="store_true")
    sp.add_argument("--expected-challenge", default=None,
                    help="fresh buyer/venue challenge that the attestation must match")
    sp.add_argument("--expected-venue-pubkey", default=None,
                    help="for tier A: the independent venue's pubkey the 2-of-2 must "
                         "use; required to trust a tier-A bond (else it fails closed)")
    sp.add_argument("--expected-ctv-template-hash", default=None,
                    help="for tier A+: buyer-derived settlement CTV template hash that "
                         "must match the descriptor covenant (else it fails closed)")

    sp = sub.add_parser("watch", help="watch a bundle's bond outpoints until spent/expired")
    sp.add_argument("bundle_json")
    sp.add_argument("--interval", type=float, default=30.0)

    sp = sub.add_parser("refund-bond", help="reclaim an expired bond via its refund leaf")
    sp.add_argument("bundle_json")
    sp.add_argument("dest_address")
    sp.add_argument("--fee-sat", type=int, default=20000)
    sp.add_argument("--broadcast", action="store_true")

    sub.add_parser("selftest", help="run the offline unit checks")

    args = p.parse_args(argv)
    if args.cmd == "selftest":
        selftest()
        return 0

    if args.cmd == "hash-terms":
        print(terms_hash_hex(_load_json(args.terms_json)))
        return 0

    rpc = _make_cli_rpc(args.cli)

    if args.cmd == "create":
        bundle = create_offer(rpc, rpc, _load_json(args.terms_json), args.descriptor,
                              challenge=args.challenge, attest=not args.no_attest)
        print(json.dumps(bundle, indent=2, sort_keys=True))
        return 0

    if args.cmd == "verify":
        report = verify_offer(rpc, _load_json(args.bundle_json), min_conf=args.min_conf,
                              require_attestation=args.require_attestation,
                              expected_challenge=args.expected_challenge,
                              expected_venue_pubkey=args.expected_venue_pubkey,
                              expected_ctv_template_hash=args.expected_ctv_template_hash)
        print(json.dumps(report.as_dict(), indent=2))
        return 0 if report.ok else 1

    if args.cmd == "watch":
        outcome = watch_offer(rpc, _load_json(args.bundle_json), interval=args.interval,
                              on_event=lambda k, d: print(f"{k}: {d}", flush=True))
        return 0 if outcome == "expired" else 2

    if args.cmd == "refund-bond":
        bundle = _load_json(args.bundle_json)
        bond = parse_bond_descriptor(bundle["bond"]["descriptor"])
        for op in bundle["bond"]["outpoints"]:
            raw = build_bond_refund(rpc, bundle["bond"]["descriptor"], op["txid"],
                                    op["vout"], args.dest_address,
                                    bond.refund_locktime, args.fee_sat)
            if args.broadcast:
                print(rpc("sendrawtransaction", raw))
            else:
                print(raw)
        return 0

    return 1


__all__ = [
    "OTC_TAG", "COINBASE_MATURITY", "RECOMMENDED_MIN_CONF", "MIN_BOND_SATS",
    "SWAP_REORG_MARGIN_BLOCKS", "REQUIRED_TERMS_FIELDS",
    "validate_terms", "canonical_terms_bytes",
    "terms_hash", "terms_hash_hex", "commitment_leaf_expr",
    "attestation_message", "soft_bond_descriptor", "venue_bond_descriptor",
    "ctv_bond_descriptor", "BondInfo", "parse_bond_descriptor", "bind_bond_descriptor", "strip_checksum",
    "add_checksum", "bond_address", "refund_key_address", "ensure_refund_attestation_descriptor",
    "sats_to_btx_str", "to_sat", "create_offer",
    "Check", "OfferVerification", "verify_offer", "watch_offer", "build_bond_refund",
    "check_swap_timeout_asymmetry", "swap_vault_descriptor", "new_preimage", "swap_hash160_hex",
    "build_swap_claim",
    "build_swap_refund", "selftest",
]

if __name__ == "__main__":
    sys.exit(main())
