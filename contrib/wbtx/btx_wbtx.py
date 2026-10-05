#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license.
"""
btx_wbtx — BTX-side SDK for wBTX bridging (drives the BTX node RPCs; no core dependency).

Scope: the BTX leg of a trustless HTLC atomic swap (bridge Model B) and helpers shared with the
federation lock-and-mint path (Model A). The EVM leg uses contrib/wbtx/evm/*.sol.

Hash domain (CRITICAL): BTX P2MR HTLC leaves lock under OP_SHA256(preimage) (32-byte digest).
The EVM contract hashes identically (`sha256` precompile). Always use the SAME 32-byte
preimage on both chains. HASH160 (RIPEMD160(SHA256(preimage))) is withdrawn for new locks.

Spend-signing & key-reuse safety (audit guidance):
  * SIGHASH_ALL: sign every BTX-leg claim/refund with SIGHASH_ALL (the node's
    buildhtlc{claim,refund} RPCs do). A non-ALL sighash leaves the spend's outputs
    third-party-malleable. Never parameterize an escrow/HTLC spend to a non-ALL type.
  * CSFS key/message uniqueness: a revealed (signature, message) pair for a CSFS key
    replays on any output reusing that key + message. This SDK uses the
    transaction-bound htlc_sha256() leaf (not a bare csfs() leaf) and the federation
    binds each attestation to a unique operation_id — keep it that way; never reuse
    a CSFS/oracle key across contexts.
  * Timeout ordering + flow: check_timeout_ordering() is NECESSARY BUT NOT SUFFICIENT
    — the preimage-holder must FUND the long (BTX) leg and CLAIM the short (EVM) leg
    first (the safe Model-B assignment), else the ordering alone does not prevent a
    claim-one-leg/refund-the-other theft. Validate depth (>= 100) before treating a
    deposit as final.

The pure helpers (hashing, descriptor construction, address derivation, deposit scan, preimage
extraction) work against any stock btxd. The funds-critical *spend* builders call the node's
buildhtlc{claim,refund} wallet RPCs, which encapsulate control-block + preimage +
PSBT-field construction and signing in audited C++ and return a fully-signed raw tx; a clearly
marked NotImplementedError is raised on older nodes that lack the RPCs (graceful degradation).

End-to-end swap flow (BTX leg of a trustless BTX<->EVM atomic swap)::

    from btx_wbtx import (HtlcLeg, add_checksum,
                          swap_address, import_watch, find_deposits, build_claim, build_refund)

    # rpc / rpc_wallet are callables: rpc(method, *params) -> parsed JSON (raise on error).
    # SAFE role assignment: the BTX funder generates the secret + hashlock, funds BTX (long leg),
    # then claims EVM (short leg) first to reveal the preimage. The recipient uses that
    # revealed preimage to claim BTX before BTX refund height.
    h256 = hashlock_from_btx_funder              # SHA256(preimage); same on BOTH chains

    leg = HtlcLeg(
        claimer_pubkey=recipient_pk,
        sender_pubkey=funder_pk,
        preimage_sha256_hex=h256,
        refund_locktime=btx_refund_height,       # absolute BTX block height
        evm_timeout_unix=evm_timeout_unix,
        now_unix=now_unix,
        current_btx_height=current_btx_height,
        min_block_seconds=fastest_plausible_block_seconds,
        reorg_margin_blocks=reorg_margin_blocks,
    )  # descriptor() performs a static ordering check only
    # REQUIRED immediately before funding. Rechecks the live tip and returns the
    # checksummed descriptor. Does not broadcast.
    desc = leg.ready_to_fund(rpc)                # mr(htlc_sha256(h256,claimer),refund(lt,sender))#checksum
    addr = swap_address(rpc, desc)               # the single P2MR lock address
    import_watch(rpc_wallet, desc)               # so the wallet indexes deposits to it
    # ... funder pays `addr`; funder also opens/claims the short EVM leg with the same hashlock ...

    dep = find_deposits(rpc_wallet, addr)[0]
    # Recipient claims BTX using the preimage that was revealed when the funder claimed EVM:
    revealed_preimage = secret_from_evm_claim
    raw = build_claim(rpc_wallet, desc, dep, revealed_preimage, recipient_dest_addr, fee_sat=1000)
    rpc("sendrawtransaction", raw)

    # OR, if the swap is abandoned, the funder refunds after refund_locktime:
    raw = build_refund(rpc_wallet, desc, dep, funder_dest_addr, btx_refund_height, fee_sat=1000)
    rpc("sendrawtransaction", raw)
"""
from __future__ import annotations
from decimal import Decimal, InvalidOperation
import hashlib
import os
import time
from dataclasses import dataclass
from typing import Callable, Optional

# An Rpc is any callable: rpc(method, *params) -> parsed JSON result (raises on error).
Rpc = Callable[..., object]


# ----------------------------- hashing / preimage -----------------------------

LOCKTIME_THRESHOLD = 500_000_000


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


def new_preimage() -> bytes:
    """A fresh 32-byte swap secret."""
    return os.urandom(32)


def btx_sha256(preimage: bytes) -> bytes:
    """SHA-256(preimage) — the 32-byte hashlock used by BOTH chains."""
    return hashlib.sha256(preimage).digest()


def btx_sha256_hex(preimage: bytes) -> str:
    return btx_sha256(preimage).hex()


def btx_hash160(preimage: bytes) -> bytes:
    """Withdrawn HASH160 domain. Kept only so recovery tooling can recognize old locks."""
    try:
        hashlib.new("ripemd160", b"")

        def _ripemd160(data: bytes) -> bytes:
            return hashlib.new("ripemd160", data).digest()
    except ValueError:
        try:
            from ._ripemd160 import ripemd160 as _ripemd160
        except ImportError:
            from _ripemd160 import ripemd160 as _ripemd160
    return _ripemd160(hashlib.sha256(preimage).digest())


def btx_hash160_hex(preimage: bytes) -> str:
    return btx_hash160(preimage).hex()


# ----------------------------- descriptors -----------------------------
# `min_block_seconds` is the FASTEST plausible BTX block interval, used to bound the
# EARLIEST wall-clock time the BTX refund height becomes spendable. It must not exceed
# the chain's block target (nPowTargetSpacing = 90s): a larger value over-estimates
# time-to-refund and would false-accept an unsafe cross-leg config. Cap it at the
# target so "fastest plausible" can never be claimed slower than target.
BTX_TARGET_BLOCK_SECONDS = 90
MAX_REASONABLE_MIN_BLOCK_SECONDS = BTX_TARGET_BLOCK_SECONDS

def check_timeout_ordering(
    btx_refund_height: int,
    evm_timeout_unix: int,
    now_unix: int,
    current_btx_height: int,
    min_block_seconds: int,
    reorg_margin_blocks: int,
) -> int:
    """Validate that BTX refund expiry safely out-lives EVM expiry.

    BTX refund locktimes are height-based. Convert the height gap into wall-clock seconds with the
    FASTEST plausible BTX block interval (`min_block_seconds`) and require:

      btx_refund_unix > evm_timeout_unix + reorg_margin_blocks * min_block_seconds

    Using the fastest plausible interval is required for safety: if difficulty drops and blocks
    arrive faster, the BTX refund is reachable sooner in wall-clock time.
    A too-large interval can falsely accept unsafe cross-leg configs.
    Returns the estimated BTX refund unix timestamp when valid; otherwise raises ValueError.
    """
    if type(btx_refund_height) is int and btx_refund_height >= LOCKTIME_THRESHOLD:
        raise ValueError(
            "btx_refund_height must be a block height; this helper compares it with an EVM unix deadline and cannot take a timestamp"
        )
    require_block_height_locktime(btx_refund_height, "btx_refund_height")
    if btx_refund_height <= 0:
        raise ValueError("btx_refund_height must be a positive absolute BTX block height")
    if current_btx_height < 0:
        raise ValueError("current_btx_height must be non-negative")
    if btx_refund_height <= current_btx_height:
        raise ValueError("btx_refund_height must be greater than current_btx_height")
    if evm_timeout_unix <= 0 or now_unix <= 0:
        raise ValueError("evm_timeout_unix and now_unix must be unix timestamps")
    if type(min_block_seconds) is not int or isinstance(min_block_seconds, bool):
        raise ValueError("min_block_seconds must be an integer number of seconds")
    if min_block_seconds <= 0:
        raise ValueError("min_block_seconds must be > 0")
    if min_block_seconds > MAX_REASONABLE_MIN_BLOCK_SECONDS:
        raise ValueError(
            f"min_block_seconds={min_block_seconds} is implausibly large; use the FASTEST plausible "
            "BTX block interval so timeout ordering is checked against earliest refund arrival "
            f"(must be <= {MAX_REASONABLE_MIN_BLOCK_SECONDS})"
        )
    if reorg_margin_blocks < 0:
        raise ValueError("reorg_margin_blocks must be >= 0")

    blocks_until_refund = btx_refund_height - current_btx_height
    btx_refund_unix = now_unix + blocks_until_refund * min_block_seconds
    required_min_refund_unix = evm_timeout_unix + reorg_margin_blocks * min_block_seconds
    if btx_refund_unix <= required_min_refund_unix:
        raise ValueError(
            "Unsafe timeout ordering: BTX refund does not out-live EVM timeout by the required margin "
            f"(btx_refund_unix={btx_refund_unix}, required>{required_min_refund_unix})"
        )
    return btx_refund_unix


def assert_timeout_ordering_at_tip(
    rpc: Rpc,
    btx_refund_height: int,
    evm_timeout_unix: int,
    min_block_seconds: int,
    reorg_margin_blocks: int,
) -> int:
    """Re-run timeout ordering against the live tip immediately before funding.

    This check is REQUIRED right before broadcasting funding for the BTX leg; descriptor-time
    checks alone can go stale while heights/timestamps advance. Uses live tip height and tip block
    time from the connected node and raises ValueError on unsafe ordering.
    """
    tip_height = rpc("getblockcount")
    if type(tip_height) is not int or tip_height < 0:
        raise ValueError(f"getblockcount returned invalid height: {tip_height!r}")
    tip_hash = rpc("getblockhash", tip_height)
    if not isinstance(tip_hash, str) or not tip_hash:
        raise ValueError(f"getblockhash returned invalid hash for height {tip_height}: {tip_hash!r}")
    tip_header = rpc("getblockheader", tip_hash)
    if not isinstance(tip_header, dict):
        raise ValueError(f"getblockheader returned invalid payload for {tip_hash}: {tip_header!r}")
    tip_time = tip_header.get("time")
    if type(tip_time) is not int or tip_time <= 0:
        raise ValueError(f"getblockheader({tip_hash}) missing valid 'time': {tip_time!r}")
    return check_timeout_ordering(
        btx_refund_height=btx_refund_height,
        evm_timeout_unix=evm_timeout_unix,
        now_unix=tip_time,
        current_btx_height=tip_height,
        min_block_seconds=min_block_seconds,
        reorg_margin_blocks=reorg_margin_blocks,
    )


@dataclass
class HtlcLeg:
    """Parameters of the BTX HTLC leg of a swap.

    descriptor() runs the static timeout check only. Immediately before sending
    funds, call ready_to_fund(rpc). That rechecks timeout ordering at the live
    tip and returns the checksummed descriptor. It does not broadcast.
    """
    claimer_pubkey: str    # recipient's ML-DSA hex (or pk_slh(...)): claims with preimage + their sig
    sender_pubkey: str     # funder's ML-DSA hex (or pk_slh(...)): refunds after locktime
    preimage_sha256_hex: str
    refund_locktime: int   # absolute BTX block height for the refund leaf
    evm_timeout_unix: int
    now_unix: int
    current_btx_height: int
    min_block_seconds: int
    reorg_margin_blocks: int

    def descriptor(self) -> str:
        """The (checksum-less) mr() descriptor; add checksum via add_checksum(rpc, ...).

        This runs the static timeout check. descriptor() alone is the static
        check. Immediately before sending funds, call ready_to_fund(rpc).
        """
        check_timeout_ordering(
            btx_refund_height=self.refund_locktime,
            evm_timeout_unix=self.evm_timeout_unix,
            now_unix=self.now_unix,
            current_btx_height=self.current_btx_height,
            min_block_seconds=self.min_block_seconds,
            reorg_margin_blocks=self.reorg_margin_blocks,
        )
        return (f"mr(htlc_sha256({self.preimage_sha256_hex},{self.claimer_pubkey}),"
                f"refund({self.refund_locktime},{self.sender_pubkey}))")

    def ready_to_fund(self, rpc: "Rpc") -> str:
        """Recheck timeout ordering at the live tip and return the checksummed descriptor.

        This is the function to call immediately before funding. It does not broadcast.
        """
        assert_timeout_ordering_at_tip(
            rpc,
            btx_refund_height=self.refund_locktime,
            evm_timeout_unix=self.evm_timeout_unix,
            min_block_seconds=self.min_block_seconds,
            reorg_margin_blocks=self.reorg_margin_blocks,
        )
        # The live check is the one that matters here. descriptor() would
        # re-apply the stored now_unix and height, which can be stale.
        descriptor = (f"mr(htlc_sha256({self.preimage_sha256_hex},{self.claimer_pubkey}),"
                      f"refund({self.refund_locktime},{self.sender_pubkey}))")
        return add_checksum(rpc, descriptor)


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


def find_deposits(rpc_wallet: Rpc, address: str, minconf: int = 100, unsafe: bool = False) -> list[Deposit]:
    """List UTXOs paid to the HTLC/lock address, enforcing a 100-conf safety floor by default."""
    if minconf < 100 and not unsafe:
        raise ValueError("minconf below safety floor (100); pass unsafe=True to override explicitly")
    out = []
    for u in rpc_wallet("listunspent", minconf, 9_999_999, [address]):
        confirmations = int(u.get("confirmations", 0))
        if confirmations < minconf:
            continue
        out.append(Deposit(u["txid"], u["vout"], str(u["amount"]), confirmations))
    return out


def to_sat(amount_btx: object) -> int:
    """Convert a BTX amount into satoshis with exact 8-decimal precision."""
    try:
        d = Decimal(str(amount_btx))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"not a BTX amount: {amount_btx!r}") from exc
    if not d.is_finite():
        raise ValueError(f"not a BTX amount: {amount_btx!r}")
    scaled = d.scaleb(8)
    if scaled != scaled.to_integral_value():
        raise ValueError(f"sub-satoshi precision: {amount_btx!r}")
    return int(scaled)


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

    Pre-funding requirement: the integration must have called
    assert_timeout_ordering_at_tip(...) immediately before broadcasting HTLC funding.

    Calls the node wallet RPC
        buildhtlcclaim "<desc#cksum>" {"txid","vout"} "<preimage_hex>" "<dest_address>" <fee_sat>
    which performs the audited control-block + preimage witness assembly and transaction signing.
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
                "(<tx_sig> <preimage> <leaf_script> <control_block>) requires injecting the "
                "sha256 preimage into the input PSBT, then walletprocesspsbt "
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

    Pre-funding requirement: the integration must have called
    assert_timeout_ordering_at_tip(...) immediately before broadcasting HTLC funding.

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

def extract_preimage(rpc: Rpc, claim_txid: str, expected_sha256_hex: str) -> Optional[bytes]:
    """
    Given a confirmed BTX HTLC CLAIM txid, recover the revealed preimage from its witness so the
    counterparty can claim the EVM leg. Scans witness stack items for one whose SHA-256
    equals the expected hashlock.
    """
    tx = rpc("getrawtransaction", claim_txid, True)
    want = bytes.fromhex(expected_sha256_hex)
    for vin in tx.get("vin", []):
        for item_hex in vin.get("txinwitness", []) or []:
            try:
                item = bytes.fromhex(item_hex)
            except ValueError:
                continue
            if btx_sha256(item) == want:
                return item
    return None


__all__ = [
    "new_preimage", "btx_sha256", "btx_sha256_hex", "btx_hash160", "btx_hash160_hex",
    "LOCKTIME_THRESHOLD", "require_block_height_locktime",
    "HtlcLeg", "add_checksum", "swap_address",
    "import_watch", "Deposit", "find_deposits", "to_sat", "sat_to_wbtx", "check_timeout_ordering",
    "assert_timeout_ordering_at_tip", "build_claim", "build_refund", "extract_preimage",
]


if __name__ == "__main__":
    now = int(time.time())
    # Unsafe: BTX timeout is too close to EVM timeout after margin.
    rejected = False
    try:
        check_timeout_ordering(
            btx_refund_height=1_000_020,
            evm_timeout_unix=now + 1_700,
            now_unix=now,
            current_btx_height=1_000_000,
            min_block_seconds=90,
            reorg_margin_blocks=2,
        )
    except ValueError:
        rejected = True
    if not rejected:
        raise SystemExit("self-check failed: unsafe timeout ordering was accepted")

    # Safe: BTX timeout remains well beyond EVM timeout + margin.
    check_timeout_ordering(
        btx_refund_height=1_000_200,
        evm_timeout_unix=now + 1_700,
        now_unix=now,
        current_btx_height=1_000_000,
        min_block_seconds=90,
        reorg_margin_blocks=2,
    )
    print("timeout ordering self-check OK")

    try:
        check_timeout_ordering(
            btx_refund_height=LOCKTIME_THRESHOLD,
            evm_timeout_unix=now + 1_700,
            now_unix=now,
            current_btx_height=1_000_000,
            min_block_seconds=90,
            reorg_margin_blocks=2,
        )
    except ValueError:
        pass
    else:
        raise SystemExit("self-check failed: timestamp-domain btx_refund_height was accepted")
    print("locktime-domain self-check OK")

    if to_sat("1e-08") != 1:
        raise SystemExit("self-check failed: to_sat('1e-08') != 1")
    if to_sat("0.00000001") != 1:
        raise SystemExit("self-check failed: to_sat('0.00000001') != 1")
    if to_sat(Decimal("50000.00000000")) != 5_000_000_000_000:
        raise SystemExit("self-check failed: to_sat(Decimal('50000.00000000')) mismatch")

    for bad_amount in ("0.000000001", "not-an-amount"):
        try:
            to_sat(bad_amount)
        except ValueError:
            pass
        else:
            raise SystemExit(f"self-check failed: to_sat({bad_amount!r}) should have raised ValueError")
    print("to_sat self-check OK")

    def _rpc_must_not_be_called(*_args) -> list[dict[str, object]]:
        raise AssertionError("rpc_wallet should not be called when minconf floor rejects request")

    try:
        find_deposits(_rpc_must_not_be_called, "btx_guard_test_address", minconf=99, unsafe=False)
    except ValueError:
        pass
    else:
        raise SystemExit("self-check failed: minconf<100 without unsafe=True did not raise")

    def _rpc_mixed_confirmations(method: str, *_params) -> list[dict[str, object]]:
        if method != "listunspent":
            raise AssertionError("unexpected RPC method")
        return [
            {"txid": "aa" * 32, "vout": 0, "amount": "0.10000000", "confirmations": 99},
            {"txid": "bb" * 32, "vout": 1, "amount": "0.20000000", "confirmations": 100},
        ]

    filtered = find_deposits(_rpc_mixed_confirmations, "btx_filter_test_address", minconf=100)
    if len(filtered) != 1 or filtered[0].txid != "bb" * 32:
        raise SystemExit("self-check failed: confirmation filtering in find_deposits is incorrect")
    print("find_deposits self-check OK")

    if btx_sha256(bytes([0x42]) * 32).hex() != "425ed4e4a36b30ea21b90e21c712c649e8214c29b7eaf68089d1039c6e55384c":
        raise SystemExit("self-check failed: btx_sha256 test vector mismatch")
    print("btx_sha256 self-check OK")
