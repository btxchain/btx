#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license.
"""
btx_otc — BTX OTC bonded-offer SDK + CLI (proof-of-offered-supply and escrow settlement).

Implements the Phase-1 tooling of doc/btx-otc-escrow-supply-validation.md: an OTC
offer only counts as real supply when it is backed by a *bonded offer vault* — coins
locked in a P2MR output whose only spend paths are (a) settle this specific offer and
(b) refund to the seller after the offer expires — with the offer terms bound to the
funding transaction via an OP_RETURN commitment so the same coins can never back two
different offers.

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
    bundle = create_offer(rpc, rpc_wallet, terms, desc)   # funds vault + OP_RETURN
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
the OP_RETURN terms-hash commitment is checked in the funding transactions, and the
optional attestation is checked with verifymessage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Callable, Optional

Rpc = Callable[..., object]

COIN = 100_000_000

# Tag prefixing every OTC bond commitment: OP_RETURN <"BTXOTC1" || sha256(terms)>.
OTC_TAG = b"BTXOTC1"
# Serialized commitment scriptPubKey: OP_RETURN(0x6a) PUSH39(0x27) tag(7) hash(32).
_COMMITMENT_SCRIPT_LEN = 1 + 1 + len(OTC_TAG) + 32


# ============================= terms canonicalization =============================

REQUIRED_TERMS_FIELDS = ("version", "amount_sats", "expiry_height", "nonce")


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
    if not isinstance(terms["amount_sats"], int) or terms["amount_sats"] <= 0:
        raise ValueError("terms.amount_sats must be a positive integer (satoshis)")
    if not isinstance(terms["expiry_height"], int) or terms["expiry_height"] <= 0:
        raise ValueError("terms.expiry_height must be a positive integer (block height)")


def canonical_terms_bytes(terms: dict) -> bytes:
    """Deterministic encoding: JSON with sorted keys, no whitespace, ASCII escapes."""
    validate_terms(terms)
    return json.dumps(terms, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def terms_hash(terms: dict) -> bytes:
    return hashlib.sha256(canonical_terms_bytes(terms)).digest()


def terms_hash_hex(terms: dict) -> str:
    return terms_hash(terms).hex()


def commitment_payload_hex(terms: dict) -> str:
    """The OP_RETURN data payload (39 bytes) binding a funding tx to one offer."""
    return (OTC_TAG + terms_hash(terms)).hex()


def commitment_script_hex(terms: dict) -> str:
    """The full expected OP_RETURN scriptPubKey hex (41 bytes serialized)."""
    payload = OTC_TAG + terms_hash(terms)
    assert len(payload) == 39
    return "6a27" + payload.hex()


def attestation_message(terms: dict, challenge: str) -> str:
    """The exact string signed/verified for the offer attestation."""
    return f"BTXOTC1|{terms_hash_hex(terms)}|{challenge}"


# ============================= bond descriptors =============================

# A descriptor key expression: raw ML-DSA hex, or pk_slh(<slh-dsa hex>).
_KEY = r"(?:[0-9a-fA-F]+|pk_slh\([0-9a-fA-F]+\))"

_TIER_B_RE = re.compile(
    rf"^mr\(({_KEY}),\{{refund\((\d+),({_KEY})\)\}}\)$")
_TIER_A_RE = re.compile(
    rf"^mr\(multi_pq\(2,({_KEY}),({_KEY})\),\{{refund\((\d+),({_KEY})\)\}}\)$")
_TIER_APLUS_RE = re.compile(
    rf"^mr\(ctv_multi_pq\(([0-9a-fA-F]{{64}}),1,({_KEY})\),\{{refund\((\d+),({_KEY})\)\}}\)$")


def soft_bond_descriptor(settle_pubkey: str, refund_locktime: int, refund_pubkey: str) -> str:
    """Tier B: seller settles unilaterally pre-expiry; refund leaf after expiry."""
    return f"mr({settle_pubkey},{{refund({refund_locktime},{refund_pubkey})}})"


def venue_bond_descriptor(settle_pubkey: str, venue_pubkey: str,
                          refund_locktime: int, refund_pubkey: str) -> str:
    """Tier A: 2-of-2 seller+venue settlement handoff; seller-only refund after expiry."""
    return (f"mr(multi_pq(2,{settle_pubkey},{venue_pubkey}),"
            f"{{refund({refund_locktime},{refund_pubkey})}})")


def ctv_bond_descriptor(ctv_template_hash_hex: str, settle_pubkey: str,
                        refund_locktime: int, refund_pubkey: str) -> str:
    """Tier A+: settlement constrained by covenant to one pre-committed transaction."""
    if len(ctv_template_hash_hex) != 64:
        raise ValueError("ctv_template_hash_hex must be 32 bytes of hex")
    return (f"mr(ctv_multi_pq({ctv_template_hash_hex},1,{settle_pubkey}),"
            f"{{refund({refund_locktime},{refund_pubkey})}})")


@dataclass
class BondInfo:
    tier: str                     # "A+", "A", or "B"
    refund_locktime: int
    refund_pubkey: str
    settle_pubkey: str
    venue_pubkey: Optional[str] = None
    ctv_hash: Optional[str] = None


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
        return BondInfo(tier="A+", ctv_hash=m.group(1).lower(), settle_pubkey=m.group(2),
                        refund_locktime=int(m.group(3)), refund_pubkey=m.group(4))
    m = _TIER_A_RE.match(desc)
    if m:
        return BondInfo(tier="A", settle_pubkey=m.group(1), venue_pubkey=m.group(2),
                        refund_locktime=int(m.group(3)), refund_pubkey=m.group(4))
    m = _TIER_B_RE.match(desc)
    if m:
        return BondInfo(tier="B", settle_pubkey=m.group(1),
                        refund_locktime=int(m.group(2)), refund_pubkey=m.group(3))
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

    Builds ONE transaction paying `terms.amount_sats` to the vault address plus the
    OP_RETURN commitment `"BTXOTC1" || sha256(canonical terms)`, via the wallet
    `send` RPC. The commitment in the funding tx is what makes the bond exclusive
    to this offer (§4.2 of the design doc).

    If `attest` is set, the bundle also carries a BIP-322 attestation: a fresh
    challenge signed (signmessage) with the wallet address that owns the refund
    key, proving the offer publisher controls the bond's exit key.
    """
    validate_terms(terms)
    bond = parse_bond_descriptor(descriptor)
    if bond.refund_locktime < terms["expiry_height"]:
        raise ValueError("refund locktime is below terms.expiry_height: the seller "
                         "could exit before the offer expires")

    desc_ck = add_checksum(rpc, descriptor)
    address = bond_address(rpc, desc_ck)

    outputs = [{address: sats_to_btx_str(terms["amount_sats"])},
               {"data": commitment_payload_hex(terms)}]
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

    if attest:
        challenge = challenge or os.urandom(16).hex()
        attest_addr = terms.get("seller_address")
        if not attest_addr:
            raise ValueError("attest=True requires terms.seller_address (a wallet "
                             "address the seller signs the challenge with); pass "
                             "attest=False to skip")
        sig = rpc_wallet("signmessage", attest_addr, attestation_message(terms, challenge))
        bundle["attestation"] = {"address": attest_addr, "challenge": challenge,
                                 "signature": sig}
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


def _get_funding_tx(rpc: Rpc, txid: str, blockhash: Optional[str],
                    funding_height: Optional[int] = None):
    """
    Verbose funding tx without requiring -txindex: try the mempool/txindex path,
    then the bundle's optional 'blockhash' hint, then the block derived from the
    UTXO's own confirmation depth (height - confirmations + 1).
    """
    try:
        return rpc("getrawtransaction", txid, True)
    except Exception:  # noqa: BLE001 - fall through to the block-scoped paths
        pass
    if blockhash:
        return rpc("getrawtransaction", txid, True, blockhash)
    if funding_height is not None:
        derived = rpc("getblockhash", funding_height)
        return rpc("getrawtransaction", txid, True, derived)
    raise RuntimeError("funding tx not retrievable (no -txindex, no blockhash hint)")


def verify_offer(rpc: Rpc, bundle: dict, min_conf: int = 20,
                 require_attestation: bool = False) -> OfferVerification:
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

    # C1 — terms are well-formed and canonicalizable.
    terms = bundle.get("terms")
    try:
        want_script_hex = commitment_script_hex(terms)
        expiry = terms["expiry_height"]
        check("terms-canonical", True, f"terms_hash={terms_hash_hex(terms)}")
    except Exception as e:  # noqa: BLE001
        check("terms-canonical", False, str(e))
        return OfferVerification(False, tier, address, 0, 0, checks)

    # C2 — descriptor parses, is a known bond shape, and its timelock covers expiry.
    try:
        desc = bundle["bond"]["descriptor"]
        desc_ck = add_checksum(rpc, desc)  # node-side parse + canonical checksum
        address = bond_address(rpc, desc_ck)
        bond = parse_bond_descriptor(desc)
        tier = bond.tier
        ok = bond.refund_locktime >= expiry
        check("descriptor-shape", ok,
              f"tier={bond.tier} refund_locktime={bond.refund_locktime} expiry={expiry}"
              + ("" if ok else " (refund unlocks BEFORE offer expiry)"))
    except Exception as e:  # noqa: BLE001
        check("descriptor-shape", False, str(e))
        return OfferVerification(False, tier, address, 0, expiry, checks)

    # C3 — outpoints exist, are unspent, pay the vault, and are confirmed.
    outpoints = bundle["bond"].get("outpoints", [])
    seen = set()
    funding_heights: dict = {}
    all_utxos_ok = len(outpoints) > 0
    if not outpoints:
        check("outpoints", False, "bundle lists no outpoints")
    for op in outpoints:
        key = (op["txid"], op["vout"])
        if key in seen:
            all_utxos_ok = check("outpoints", False, f"duplicate outpoint {key}") and all_utxos_ok
            continue
        seen.add(key)
        utxo = rpc("gettxout", op["txid"], op["vout"], False)
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
        if confs < min_conf:
            all_utxos_ok = check("outpoints", False,
                                 f"{op['txid']}:{op['vout']} has {confs} confirmations "
                                 f"(< {min_conf})") and all_utxos_ok
            continue
        verified_sats += to_sat(utxo["value"])
        funding_heights[key] = rpc("getblockcount") - confs + 1
        check("outpoints", True, f"{op['txid']}:{op['vout']} {utxo['value']} BTX, {confs} conf")

    amount_ok = verified_sats >= terms["amount_sats"]
    check("amount", amount_ok,
          f"verified {verified_sats} sats vs terms.amount_sats {terms['amount_sats']}")
    all_utxos_ok = all_utxos_ok and amount_ok

    # C4 — every funding tx carries the OP_RETURN commitment to THESE terms.
    commit_ok = True
    for op in outpoints:
        if (op["txid"], op["vout"]) not in seen:
            continue
        try:
            fund_tx = _get_funding_tx(rpc, op["txid"], op.get("blockhash"),
                                      funding_heights.get((op["txid"], op["vout"])))
        except Exception as e:  # noqa: BLE001
            commit_ok = check("commitment", False,
                              f"{op['txid']}: funding tx unavailable ({e}); add a "
                              "'blockhash' hint to the outpoint or run with -txindex") and commit_ok
            continue
        found = any(out.get("scriptPubKey", {}).get("hex", "").lower() == want_script_hex
                    for out in fund_tx.get("vout", []))
        commit_ok = check("commitment", found,
                          f"{op['txid']}: OP_RETURN BTXOTC1||terms_hash "
                          + ("present" if found else "MISSING or committed to different terms "
                             "(possible double-pledge)")) and commit_ok

    # C5 — offer not already expired.
    height = rpc("getblockcount")
    not_expired = height < expiry
    check("not-expired", not_expired, f"height={height} expiry={expiry}")

    # C6 — attestation (freshness / publisher-controls-a-seller-key). Optional:
    # binding is 'declared' (attestation address is whatever the bundle names),
    # so it proves challenge freshness and control of that address — the hard
    # supply guarantees come from C2/C3/C4, not from this signature.
    att = bundle.get("attestation")
    att_ok = True
    if att:
        try:
            msg = attestation_message(terms, att["challenge"])
            att_ok = bool(rpc("verifymessage", att["address"], att["signature"], msg))
            check("attestation", att_ok, f"address={att['address']}")
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
            if rpc("gettxout", op["txid"], op["vout"], False) is None:
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
                         {"txid": txid, "vout": vout}, dest_address, locktime, fee_sat)
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


def swap_vault_descriptor(internal_pubkey: str, preimage_hash160_hex: str,
                          claimer_pubkey: str, refund_locktime: int,
                          sender_pubkey: str) -> str:
    """Stage-2 HTLC settlement vault (identical shape to the wBTX Model-B leg)."""
    return (f"mr({internal_pubkey},"
            f"{{htlc({preimage_hash160_hex},{claimer_pubkey}),"
            f"refund({refund_locktime},{sender_pubkey})}})")


def new_preimage() -> bytes:
    return os.urandom(32)


def swap_hash160_hex(preimage: bytes) -> str:
    """RIPEMD160(SHA256(preimage)) — same hashlock domain as the EVM HTLC contract."""
    return hashlib.new("ripemd160", hashlib.sha256(preimage).digest()).hexdigest()


def build_swap_claim(rpc_wallet: Rpc, descriptor_with_checksum: str, txid: str,
                     vout: int, preimage: bytes, dest_address: str,
                     fee_sat: int = 20000) -> str:
    """Buyer claims the settlement vault with the preimage (reveals it on-chain)."""
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
    return build_bond_refund(rpc_wallet, descriptor_with_checksum, txid, vout,
                             dest_address, locktime, fee_sat)


# ============================= offline selftest =============================

def selftest() -> None:
    """Offline sanity of the pure helpers (no node needed). Raises on failure."""
    terms = {"version": 1, "amount_sats": 12345, "expiry_height": 100,
             "nonce": "00" * 16, "b": [1, {"a": "x"}]}
    # Canonicalization is order-insensitive and whitespace-free.
    reordered = json.loads(json.dumps(terms)[::-1][::-1])
    assert terms_hash(terms) == terms_hash(dict(reversed(list(reordered.items()))))
    assert canonical_terms_bytes(terms) == canonical_terms_bytes(reordered)
    # Floats are rejected.
    try:
        terms_hash({"version": 1, "amount_sats": 1, "expiry_height": 1,
                    "nonce": "00", "price": 1.5})
        raise AssertionError("float in terms must be rejected")
    except ValueError:
        pass
    # Commitment script framing.
    assert commitment_script_hex(terms) == "6a27" + (OTC_TAG + terms_hash(terms)).hex()
    assert len(bytes.fromhex(commitment_script_hex(terms))) == _COMMITMENT_SCRIPT_LEN
    # Descriptor round-trips for all tiers.
    k1, k2, k3 = "aa" * 1312, "bb" * 1312, "cc" * 1312
    b = parse_bond_descriptor(soft_bond_descriptor(k1, 900, k2))
    assert (b.tier, b.refund_locktime, b.settle_pubkey, b.refund_pubkey) == ("B", 900, k1, k2)
    a = parse_bond_descriptor(venue_bond_descriptor(k1, k3, 901, k2) + "#abcd1234")
    assert (a.tier, a.venue_pubkey, a.refund_locktime) == ("A", k3, 901)
    ap = parse_bond_descriptor(ctv_bond_descriptor("11" * 32, k1, 902, k2))
    assert (ap.tier, ap.ctv_hash, ap.refund_locktime) == ("A+", "11" * 32, 902)
    # SLH-DSA key forms parse too.
    parse_bond_descriptor(soft_bond_descriptor(f"pk_slh({'dd' * 32})", 900, k2))
    # Unknown shapes fail closed.
    for bad in (f"mr({k1})",                                             # no refund leaf
                f"mr({k1},{{htlc({'ee' * 20},{k2}),refund(900,{k2})}})",  # extra leaf
                f"mr(multi_pq(1,{k1},{k3}),{{refund(900,{k2})}})"):       # 1-of-2 settle
        try:
            parse_bond_descriptor(bad)
            raise AssertionError(f"must fail closed: {bad[:40]}...")
        except ValueError:
            pass
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
            return json.loads(text)
        except json.JSONDecodeError:
            return text  # bare-string results (e.g. signmessage)
    return rpc


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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
    sp.add_argument("--min-conf", type=int, default=20)
    sp.add_argument("--require-attestation", action="store_true")

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
                              require_attestation=args.require_attestation)
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
    "OTC_TAG", "REQUIRED_TERMS_FIELDS", "validate_terms", "canonical_terms_bytes",
    "terms_hash", "terms_hash_hex", "commitment_payload_hex", "commitment_script_hex",
    "attestation_message", "soft_bond_descriptor", "venue_bond_descriptor",
    "ctv_bond_descriptor", "BondInfo", "parse_bond_descriptor", "strip_checksum",
    "add_checksum", "bond_address", "sats_to_btx_str", "to_sat", "create_offer",
    "Check", "OfferVerification", "verify_offer", "watch_offer", "build_bond_refund",
    "swap_vault_descriptor", "new_preimage", "swap_hash160_hex", "build_swap_claim",
    "build_swap_refund", "selftest",
]

if __name__ == "__main__":
    sys.exit(main())
