#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license.
"""
btx_wbtx — BTX-side SDK for wBTX bridging (drives the BTX node RPCs; no core dependency).

Scope: the BTX leg of a trustless HTLC atomic swap (bridge Model B) and helpers shared with the
federation lock-and-mint path (Model A). The EVM leg uses contrib/wbtx/evm/*.sol.

Hash domain (CRITICAL): BTX P2MR HTLC leaves lock under OP_HASH160 = RIPEMD160(SHA256(preimage)).
The EVM contract hashes identically (sha256 + ripemd160 precompiles). Always use the SAME 32-byte
preimage on both chains.

The pure helpers (hashing, descriptor construction, address derivation, deposit scan, preimage
extraction) work against any stock btxd. The funds-critical *spend* builders call the node's
buildhtlc{claim,refund} wallet RPCs, which encapsulate control-block + CSFS-message + preimage +
PSBT-field construction and signing in audited C++ and return a fully-signed raw tx; a clearly
marked NotImplementedError is raised on older nodes that lack the RPCs (graceful degradation).

End-to-end swap flow (BTX leg of a trustless BTX<->EVM atomic swap)::

    from btx_wbtx import (new_preimage, btx_hash160_hex, HtlcLeg, add_checksum,
                          swap_address, import_watch, find_deposits, build_claim, build_refund)

    # rpc / rpc_wallet are callables: rpc(method, *params) -> parsed JSON (raise on error).
    secret = new_preimage()                      # 32-byte swap secret (keep private until claim)
    h160   = btx_hash160_hex(secret)             # == RIPEMD160(SHA256(secret)); use on BOTH chains

    leg = HtlcLeg(internal_pubkey=internal_pk, claimer_pubkey=recipient_pk,
                  sender_pubkey=funder_pk, preimage_hash160_hex=h160,
                  refund_locktime=btx_refund_height)   # BTX timeout STRICTLY > EVM timeout
    desc = add_checksum(rpc, leg.descriptor())   # mr(internal,{htlc(h160,claimer),refund(lt,sender)})
    addr = swap_address(rpc, desc)               # the single P2MR lock address
    import_watch(rpc_wallet, desc)               # so the wallet indexes deposits to it
    # ... funder pays `addr`; counterparty opens the EVM leg under the SAME hashlock h160 ...

    dep = find_deposits(rpc_wallet, addr)[0]
    # Recipient claims, REVEALING the preimage on-chain (CSFS sig added by the wallet):
    raw = build_claim(rpc_wallet, desc, dep, secret, recipient_dest_addr, fee_sat=1000)
    rpc("sendrawtransaction", raw)               # preimage now public -> claim the EVM leg

    # OR, if the swap is abandoned, the funder refunds after refund_locktime:
    raw = build_refund(rpc_wallet, desc, dep, funder_dest_addr, btx_refund_height, fee_sat=1000)
    rpc("sendrawtransaction", raw)
"""
from __future__ import annotations
import hashlib
import os
from dataclasses import dataclass
from typing import Callable, Optional

# An Rpc is any callable: rpc(method, *params) -> parsed JSON result (raises on error).
Rpc = Callable[..., object]


# ----------------------------- hashing / preimage -----------------------------

def new_preimage() -> bytes:
    """A fresh 32-byte swap secret."""
    return os.urandom(32)


def btx_hash160(preimage: bytes) -> bytes:
    """RIPEMD160(SHA256(preimage)) — the 20-byte hashlock used by BOTH chains."""
    return hashlib.new("ripemd160", hashlib.sha256(preimage).digest()).digest()


def btx_hash160_hex(preimage: bytes) -> str:
    return btx_hash160(preimage).hex()


# ----------------------------- descriptors -----------------------------

@dataclass
class HtlcLeg:
    """Parameters of the BTX HTLC leg of a swap."""
    internal_pubkey: str   # ML-DSA hex (or pk_slh(<slh hex>)) — the key-path internal key
    claimer_pubkey: str    # recipient's ML-DSA hex (or pk_slh(...)): claims with preimage + their sig
    sender_pubkey: str     # funder's ML-DSA hex (or pk_slh(...)): refunds after locktime
    preimage_hash160_hex: str
    refund_locktime: int   # absolute block height (or unix time) for the refund leaf

    def descriptor(self) -> str:
        """The (checksum-less) mr() descriptor; add a checksum via add_checksum(rpc, ...)."""
        return (f"mr({self.internal_pubkey},"
                f"{{htlc({self.preimage_hash160_hex},{self.claimer_pubkey}),"
                f"refund({self.refund_locktime},{self.sender_pubkey})}})")


def add_checksum(rpc: Rpc, descriptor: str) -> str:
    """Return descriptor#checksum using the node's getdescriptorinfo (also validates parse)."""
    info = rpc("getdescriptorinfo", descriptor)
    return f"{descriptor}#{info['checksum']}"


def swap_address(rpc: Rpc, descriptor_with_checksum: str) -> str:
    """Derive the single P2MR address for an mr() HTLC descriptor."""
    addrs = rpc("deriveaddresses", descriptor_with_checksum)
    return addrs[0]


def import_watch(rpc_wallet: Rpc, descriptor_with_checksum: str) -> None:
    """Import the HTLC descriptor (watch-only) so the wallet indexes deposits to it."""
    rpc_wallet("importdescriptors",
               [{"desc": descriptor_with_checksum, "timestamp": "now", "internal": False}])


# ----------------------------- deposit detection -----------------------------

@dataclass
class Deposit:
    txid: str
    vout: int
    amount_btx: str   # decimal string as returned by the node
    confirmations: int


def find_deposits(rpc_wallet: Rpc, address: str, minconf: int = 0) -> list[Deposit]:
    """List UTXOs paid to the (imported) HTLC/lock address — for relayers/orchestrators."""
    out = []
    for u in rpc_wallet("listunspent", minconf, 9_999_999, [address]):
        out.append(Deposit(u["txid"], u["vout"], str(u["amount"]), int(u.get("confirmations", 0))))
    return out


def to_sat(amount_btx: str) -> int:
    """Convert a node decimal-BTX string to int satoshis (8 dp) exactly."""
    whole, _, frac = amount_btx.partition(".")
    frac = (frac + "00000000")[:8]
    return int(whole) * 100_000_000 + int(frac)


def sat_to_wbtx(amount_sat: int) -> int:
    """wBTX (18-dec) amount for a satoshi amount: sat * 1e10."""
    return amount_sat * 10**10


# ----------------------------- spend legs (claim / refund) -----------------------------

def _is_unknown_method(exc: Exception) -> bool:
    """True iff `exc` looks like a JSON-RPC 'method not found' (-32601) for a missing RPC.

    Used to distinguish "this btxd lacks the buildhtlc* RPCs" (-> graceful NotImplementedError)
    from a genuine call-time error like a bad preimage or an unreached locktime (-> re-raise).
    """
    err = getattr(exc, "error", None)
    code = err.get("code") if isinstance(err, dict) else getattr(exc, "code", None)
    if code == -32601:
        return True
    msg = str(exc).lower()
    return "method not found" in msg or "unknown command" in msg


def build_claim(rpc_wallet: Rpc, descriptor_with_checksum: str, deposit: Deposit,
                preimage: bytes, dest_address: str, fee_sat: int = 1000) -> str:
    """
    Build+sign the HTLC CLAIM (recipient) spending `deposit` to `dest_address`, revealing `preimage`.

    Calls the node wallet RPC
        buildhtlcclaim "<desc#cksum>" {"txid","vout"} "<preimage_hex>" "<dest_address>" <fee_sat>
    which performs the audited control-block + CSFS-message + preimage witness assembly and signing.
    Returns the fully-signed raw tx hex ready for sendrawtransaction; the broadcast publishes the
    preimage on-chain so the counterparty can claim the EVM leg.
    """
    try:
        res = rpc_wallet("buildhtlcclaim", descriptor_with_checksum,
                         {"txid": deposit.txid, "vout": deposit.vout},
                         preimage.hex(), dest_address, fee_sat)
    except Exception as e:  # noqa: BLE001
        if _is_unknown_method(e):
            raise NotImplementedError(
                "buildhtlcclaim RPC unavailable on this node. The HTLC claim witness "
                "(<0x01> <csfs_sig> <preimage> <leaf_script> <control_block>) requires injecting the "
                "hash160 preimage and the P2MR CSFS message into the input PSBT, then walletprocesspsbt "
                "+ finalizepsbt. Use a btxd build that includes the buildhtlcclaim/buildhtlcrefund "
                "bridging RPCs, or construct the PSBT fields manually (see contrib/wbtx/README.md)."
            ) from e
        raise  # genuine RPC error (e.g. wrong preimage / insufficient funds) — surface as-is
    if not res.get("complete", False):
        raise RuntimeError("buildhtlcclaim returned an incomplete (unsigned) transaction; "
                           "check the descriptor, the preimage, and that the wallet owns the claimer key")
    return res["hex"]


def build_refund(rpc_wallet: Rpc, descriptor_with_checksum: str, deposit: Deposit,
                 dest_address: str, locktime: int, fee_sat: int = 1000) -> str:
    """
    Build+sign the HTLC REFUND (sender) reclaiming `deposit` to `dest_address` after `locktime`.

    Calls the node wallet RPC
        buildhtlcrefund "<desc#cksum>" {"txid","vout"} "<dest_address>" <locktime> <fee_sat>
    The output is only spendable once the chain tip is at/after `locktime` (the refund leaf's
    timelock); the node sets nLockTime/sequence accordingly. Returns the signed raw tx hex.
    """
    try:
        res = rpc_wallet("buildhtlcrefund", descriptor_with_checksum,
                         {"txid": deposit.txid, "vout": deposit.vout},
                         dest_address, locktime, fee_sat)
    except Exception as e:  # noqa: BLE001
        if _is_unknown_method(e):
            raise NotImplementedError(
                "buildhtlcrefund RPC unavailable on this node. Use a btxd build that includes the "
                "buildhtlcclaim/buildhtlcrefund bridging RPCs, or see contrib/wbtx/README.md for the "
                "manual PSBT refund recipe."
            ) from e
        raise  # genuine RPC error (e.g. locktime not yet reached) — surface as-is
    if not res.get("complete", False):
        raise RuntimeError("buildhtlcrefund returned an incomplete (unsigned) transaction; "
                           "check the locktime has been reached and the wallet owns the sender key")
    return res["hex"]


# ----------------------------- preimage extraction (for the EVM leg) -----------------------------

def extract_preimage(rpc: Rpc, claim_txid: str, expected_hash160_hex: str) -> Optional[bytes]:
    """
    Given a confirmed BTX HTLC CLAIM txid, recover the revealed preimage from its witness so the
    counterparty can claim the EVM leg. Scans witness stack items for one whose RIPEMD160(SHA256())
    equals the expected hashlock.
    """
    tx = rpc("getrawtransaction", claim_txid, True)
    want = bytes.fromhex(expected_hash160_hex)
    for vin in tx.get("vin", []):
        for item_hex in vin.get("txinwitness", []) or []:
            try:
                item = bytes.fromhex(item_hex)
            except ValueError:
                continue
            if btx_hash160(item) == want:
                return item
    return None


__all__ = [
    "new_preimage", "btx_hash160", "btx_hash160_hex", "HtlcLeg", "add_checksum", "swap_address",
    "import_watch", "Deposit", "find_deposits", "to_sat", "sat_to_wbtx", "build_claim",
    "build_refund", "extract_preimage",
]
