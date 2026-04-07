#!/usr/bin/env python3
# Copyright (c) 2015-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utilities for manipulating blocks and transactions."""

import struct
import time
import unittest

from .address import (
    address_to_scriptpubkey,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
    script_to_p2sh_p2wsh,
    script_to_p2wsh,
)
from .messages import (
    CBlock,
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
    hash256,
    lookup_solved_block_index,
    ser_uint256,
    seed_solved_block_index,
    tx_from_hex,
    MAX_BLOCK_SIGOPS_COST,
    uint256_from_compact,
    uint256_to_compact,
    uint256_from_str,
    WITNESS_SCALE_FACTOR,
)
from .script import (
    CScript,
    CScriptNum,
    CScriptOp,
    OP_0,
    OP_RETURN,
    OP_TRUE,
)
from .script_util import (
    key_to_p2pk_script,
    key_to_p2pkh_script,
    key_to_p2wpkh_script,
    keys_to_multisig_script,
    script_to_p2wsh_script,
)
from .util import assert_equal

MAX_BLOCK_SIGOPS = MAX_BLOCK_SIGOPS_COST // WITNESS_SCALE_FACTOR
MAX_BLOCK_SIGOPS_WEIGHT = MAX_BLOCK_SIGOPS * WITNESS_SCALE_FACTOR
MAX_STANDARD_TX_WEIGHT = 1200000

# Genesis block time (regtest)
TIME_GENESIS_BLOCK = 1296688602

MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60

# Coinbase transaction outputs can only be spent after this number of new blocks (network rule)
COINBASE_MATURITY = 100

# From BIP141
WITNESS_COMMITMENT_HEADER = b"\xaa\x21\xa9\xed"

NORMAL_GBT_REQUEST_PARAMS = {"rules": ["segwit"]}
VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4
MIN_BLOCKS_TO_KEEP = 288

REGTEST_RETARGET_PERIOD = 150
REGTEST_INITIAL_SUBSIDY = 20

# BTX regtest genesis metadata (see src/kernel/chainparams.cpp).
REGTEST_GENESIS_HASH = int("61f7f9829d2930b8920a8e1d221473f3856c77d8786e3969468c762497c01187", 16)
REGTEST_GENESIS_N_BITS = 0x207fffff
REGTEST_POW_LIMIT = (1 << 256) - 1
UINT256_MASK = (1 << 256) - 1
REGTEST_POW_LIMIT_N_BITS = uint256_to_compact(REGTEST_POW_LIMIT)
assert_equal(REGTEST_POW_LIMIT_N_BITS, 0x2100ffff)
REGTEST_MATMUL_DGW_WINDOW = 180
REGTEST_MATMUL_TARGET_SPACING = 90
# Compatibility aliases for tests that still import historical names.
REGTEST_KAWPOW_DGW_WINDOW = REGTEST_MATMUL_DGW_WINDOW
REGTEST_KAWPOW_TARGET_SPACING = REGTEST_MATMUL_TARGET_SPACING
BTX_MAX_TXOUT_SCRIPT_SIZE = 34

# Keep historical constant name for callers that still import it.
REGTEST_N_BITS = REGTEST_GENESIS_N_BITS
REGTEST_TARGET = 0x7fffff0000000000000000000000000000000000000000000000000000000000
assert_equal(uint256_from_compact(REGTEST_N_BITS), REGTEST_TARGET)

DIFF_1_N_BITS = 0x1d00ffff
DIFF_1_TARGET = 0x00000000ffff0000000000000000000000000000000000000000000000000000
assert_equal(uint256_from_compact(DIFF_1_N_BITS), DIFF_1_TARGET)

DIFF_4_N_BITS = 0x1c3fffc0
DIFF_4_TARGET = int(DIFF_1_TARGET / 4)
assert_equal(uint256_from_compact(DIFF_4_N_BITS), DIFF_4_TARGET)

# Seed solved-header metadata with the BTX regtest genesis so handcrafted
# block building can derive correct DGW bits from the very first child.
seed_solved_block_index(
    block_hash=REGTEST_GENESIS_HASH,
    prev_hash=0,
    height=0,
    n_time=TIME_GENESIS_BLOCK,
    n_bits=REGTEST_GENESIS_N_BITS,
)

def nbits_str(nbits):
    return f"{nbits:08x}"

def target_str(target):
    return f"{target:064x}"

def _btx_regtest_next_work_required(prev_hash):
    """Mirror BTX regtest DGW work selection for handcrafted blocks."""
    prev_meta = lookup_solved_block_index(prev_hash)
    if prev_meta is None:
        return None

    prev_height = prev_meta["height"]
    if prev_height is None:
        return None

    # pow.cpp::GetNextWorkRequired() returns powLimit for early DGW history.
    if prev_height < REGTEST_MATMUL_DGW_WINDOW:
        return REGTEST_POW_LIMIT_N_BITS

    cursor = prev_meta
    avg_target = 0
    for count in range(1, REGTEST_MATMUL_DGW_WINDOW + 1):
        target = uint256_from_compact(cursor["n_bits"])
        if count == 1:
            avg_target = target
        else:
            # DGW in consensus uses fixed-width arith_uint256 math. Preserve the
            # same overflow behavior before integer division.
            avg_target = ((avg_target * count) + target) & UINT256_MASK
            avg_target //= (count + 1)

        if count != REGTEST_MATMUL_DGW_WINDOW:
            cursor = lookup_solved_block_index(cursor["prev_hash"])
            if cursor is None:
                return prev_meta["n_bits"]

    actual_timespan = prev_meta["n_time"] - cursor["n_time"]
    target_timespan = REGTEST_MATMUL_DGW_WINDOW * REGTEST_MATMUL_TARGET_SPACING
    actual_timespan = max(target_timespan // 3, min(actual_timespan, target_timespan * 3))

    # arith_uint256 multiplication overflows modulo 2^256 before division.
    new_target = (avg_target * actual_timespan) & UINT256_MASK
    new_target //= target_timespan
    new_target = min(new_target, REGTEST_POW_LIMIT)
    return uint256_to_compact(new_target)

def create_block(hashprev=None, coinbase=None, ntime=None, *, version=None, tmpl=None, txlist=None):
    """Create a block (with regtest difficulty)."""
    block = CBlock()
    if tmpl is None:
        tmpl = {}
    block.nVersion = version or tmpl.get('version') or VERSIONBITS_LAST_OLD_BLOCK_VERSION
    block.nTime = ntime or tmpl.get('curtime') or int(time.time() + 600)
    block.hashPrevBlock = hashprev or int(tmpl['previousblockhash'], 0x10)
    if tmpl and tmpl.get('bits') is not None:
        block.nBits = struct.unpack('>I', bytes.fromhex(tmpl['bits']))[0]
    else:
        prev_meta = lookup_solved_block_index(block.hashPrevBlock)
        if prev_meta is not None and prev_meta.get("n_bits") is not None:
            # BTX regtest runs with fPowNoRetargeting=true; inherit parent nBits.
            block.nBits = prev_meta["n_bits"]
        else:
            block.nBits = REGTEST_N_BITS
    if coinbase is None:
        coinbase = create_coinbase(height=tmpl['height'])
    block.vtx.append(coinbase)
    if txlist:
        for tx in txlist:
            if not hasattr(tx, 'calc_sha256'):
                tx = tx_from_hex(tx)
            block.vtx.append(tx)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block

def get_witness_script(witness_root, witness_nonce):
    witness_commitment = uint256_from_str(hash256(ser_uint256(witness_root) + ser_uint256(witness_nonce)))
    output_data = WITNESS_COMMITMENT_HEADER + ser_uint256(witness_commitment)
    return CScript([OP_RETURN, output_data])

def add_witness_commitment(block, nonce=0):
    """Add a witness commitment to the block's coinbase transaction.

    According to BIP141, blocks with witness rules active must commit to the
    hash of all in-block transactions including witness."""
    # First calculate the merkle root of the block's
    # transactions, with witnesses.
    witness_nonce = nonce
    witness_root = block.calc_witness_merkle_root()
    # witness_nonce should go to coinbase witness.
    block.vtx[0].wit.vtxinwit = [CTxInWitness()]
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(witness_nonce)]

    # witness commitment is the last OP_RETURN output in coinbase
    block.vtx[0].vout.append(CTxOut(0, get_witness_script(witness_root, witness_nonce)))
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.rehash()


def script_BIP34_coinbase_height(height):
    if height <= 16:
        res = CScriptOp.encode_op_n(height)
        # Append dummy to increase scriptSig size to 2 (see bad-cb-length consensus rule)
        return CScript([res, OP_0])
    return CScript([CScriptNum(height)])


def create_coinbase(height, pubkey=None, *, script_pubkey=None, extra_output_script=None, fees=0, nValue=REGTEST_INITIAL_SUBSIDY, halving_period=REGTEST_RETARGET_PERIOD):
    """Create a coinbase transaction.

    If pubkey is passed in, the coinbase output will be a P2PK output;
    otherwise an anyone-can-spend output.

    If extra_output_script is given, make a 0-value output to that
    script. This is useful to pad block weight/sigops as needed. """
    coinbase = CTransaction()
    coinbase.vin.append(CTxIn(COutPoint(0, 0xffffffff), script_BIP34_coinbase_height(height), SEQUENCE_FINAL))
    coinbaseoutput = CTxOut()
    coinbaseoutput.nValue = nValue * COIN
    if nValue == REGTEST_INITIAL_SUBSIDY:
        halvings = int(height / halving_period)
        coinbaseoutput.nValue >>= halvings
        coinbaseoutput.nValue += fees
    if pubkey is not None:
        p2pk_script = key_to_p2pk_script(pubkey)
        # BTX reduced data limits reject 35-byte compressed P2PK scripts.
        if len(p2pk_script) <= BTX_MAX_TXOUT_SCRIPT_SIZE:
            coinbaseoutput.scriptPubKey = p2pk_script
        else:
            coinbaseoutput.scriptPubKey = key_to_p2pkh_script(pubkey)
    elif script_pubkey is not None:
        coinbaseoutput.scriptPubKey = script_pubkey
    else:
        coinbaseoutput.scriptPubKey = CScript([OP_TRUE])
    coinbase.vout = [coinbaseoutput]
    if extra_output_script is not None:
        coinbaseoutput2 = CTxOut()
        coinbaseoutput2.nValue = 0
        coinbaseoutput2.scriptPubKey = extra_output_script
        coinbase.vout.append(coinbaseoutput2)
    coinbase.calc_sha256()
    return coinbase

def create_tx_with_script(prevtx, n, script_sig=b"", *, amount, output_script=None):
    """Return one-input, one-output transaction object
       spending the prevtx's n-th output with the given amount.

       Can optionally pass scriptPubKey and scriptSig, default is anyone-can-spend output.
    """
    if output_script is None:
        output_script = CScript()
    tx = CTransaction()
    assert n < len(prevtx.vout)
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), script_sig, SEQUENCE_FINAL))
    tx.vout.append(CTxOut(amount, output_script))
    tx.calc_sha256()
    return tx

def get_legacy_sigopcount_block(block, accurate=True):
    count = 0
    for tx in block.vtx:
        count += get_legacy_sigopcount_tx(tx, accurate)
    return count

def get_legacy_sigopcount_tx(tx, accurate=True):
    count = 0
    for i in tx.vout:
        count += i.scriptPubKey.GetSigOpCount(accurate)
    for j in tx.vin:
        # scriptSig might be of type bytes, so convert to CScript for the moment
        count += CScript(j.scriptSig).GetSigOpCount(accurate)
    return count

def witness_script(use_p2wsh, pubkey):
    """Create a scriptPubKey for a pay-to-witness TxOut.

    This is either a P2WPKH output for the given pubkey, or a P2WSH output of a
    1-of-1 multisig for the given pubkey. Returns the hex encoding of the
    scriptPubKey."""
    if not use_p2wsh:
        # P2WPKH instead
        pkscript = key_to_p2wpkh_script(pubkey)
    else:
        # 1-of-1 multisig
        witness_script = keys_to_multisig_script([pubkey])
        pkscript = script_to_p2wsh_script(witness_script)
    return pkscript.hex()

def create_witness_tx(node, use_p2wsh, utxo, pubkey, encode_p2sh, amount):
    """Return a transaction (in hex) that spends the given utxo to a segwit output.

    Optionally wrap the segwit output using P2SH."""
    if use_p2wsh:
        program = keys_to_multisig_script([pubkey])
        addr = script_to_p2sh_p2wsh(program) if encode_p2sh else script_to_p2wsh(program)
    else:
        addr = key_to_p2sh_p2wpkh(pubkey) if encode_p2sh else key_to_p2wpkh(pubkey)
    if not encode_p2sh:
        assert_equal(address_to_scriptpubkey(addr).hex(), witness_script(use_p2wsh, pubkey))
    return node.createrawtransaction([utxo], {addr: amount})

def send_to_witness(use_p2wsh, node, utxo, pubkey, encode_p2sh, amount, sign=True, insert_redeem_script=""):
    """Create a transaction spending a given utxo to a segwit output.

    The output corresponds to the given pubkey: use_p2wsh determines whether to
    use P2WPKH or P2WSH; encode_p2sh determines whether to wrap in P2SH.
    sign=True will have the given node sign the transaction.
    insert_redeem_script will be added to the scriptSig, if given."""
    tx_to_witness = create_witness_tx(node, use_p2wsh, utxo, pubkey, encode_p2sh, amount)
    if (sign):
        signed = node.signrawtransactionwithwallet(tx_to_witness)
        assert "errors" not in signed or len(["errors"]) == 0
        # Crafted witness tests intentionally vary fee profiles; bypass maxfeerate checks.
        return node.sendrawtransaction(signed["hex"], maxfeerate=0)
    else:
        if (insert_redeem_script):
            tx = tx_from_hex(tx_to_witness)
            tx.vin[0].scriptSig += CScript([bytes.fromhex(insert_redeem_script)])
            tx_to_witness = tx.serialize().hex()

    return node.sendrawtransaction(tx_to_witness, maxfeerate=0)

class TestFrameworkBlockTools(unittest.TestCase):
    def test_create_coinbase(self):
        height = 20
        coinbase_tx = create_coinbase(height=height)
        assert_equal(CScriptNum.decode(coinbase_tx.vin[0].scriptSig), height)

    def test_regtest_dgw_starts_at_pow_limit(self):
        # Child of genesis must use powLimit compact bits under BTX regtest DGW.
        assert_equal(_btx_regtest_next_work_required(REGTEST_GENESIS_HASH), REGTEST_POW_LIMIT_N_BITS)

    def test_regtest_dgw_tight_spacing_raises_difficulty(self):
        # Build a synthetic 181-block history with 1-second spacing and verify
        # DGW clamps timespan and raises difficulty above powLimit target.
        base_hash = (1 << 255) + 0x123456
        seed_solved_block_index(
            block_hash=base_hash,
            prev_hash=0,
            height=0,
            n_time=TIME_GENESIS_BLOCK,
            n_bits=REGTEST_POW_LIMIT_N_BITS,
        )

        prev_hash = base_hash
        for height in range(1, REGTEST_MATMUL_DGW_WINDOW + 1):
            block_hash = base_hash + height
            seed_solved_block_index(
                block_hash=block_hash,
                prev_hash=prev_hash,
                height=height,
                n_time=TIME_GENESIS_BLOCK + height,
                n_bits=REGTEST_POW_LIMIT_N_BITS,
            )
            prev_hash = block_hash

        next_bits = _btx_regtest_next_work_required(prev_hash)
        assert next_bits is not None
        assert next_bits != REGTEST_POW_LIMIT_N_BITS
        assert uint256_from_compact(next_bits) < REGTEST_POW_LIMIT

    def test_regtest_dgw_first_retarget_matches_consensus_overflow_math(self):
        # With regtest's 2100ffff pre-DGW bits and 1-second spacing, fixed-width
        # 256-bit overflow in DGW averaging yields this known first retarget.
        base_hash = (1 << 255) + 0xABCDEF
        seed_solved_block_index(
            block_hash=base_hash,
            prev_hash=0,
            height=0,
            n_time=TIME_GENESIS_BLOCK,
            n_bits=REGTEST_POW_LIMIT_N_BITS,
        )

        prev_hash = base_hash
        for height in range(1, REGTEST_MATMUL_DGW_WINDOW + 1):
            block_hash = base_hash + height
            seed_solved_block_index(
                block_hash=block_hash,
                prev_hash=prev_hash,
                height=height,
                n_time=TIME_GENESIS_BLOCK + height,
                n_bits=REGTEST_POW_LIMIT_N_BITS,
            )
            prev_hash = block_hash

        assert_equal(_btx_regtest_next_work_required(prev_hash), 0x1F016C64)

    def test_create_coinbase_pubkey_falls_back_to_p2pkh_under_btx_limits(self):
        pubkey = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        assert_equal(len(key_to_p2pk_script(pubkey)), 35)

        coinbase_tx = create_coinbase(height=1, pubkey=pubkey)
        assert_equal(coinbase_tx.vout[0].scriptPubKey, key_to_p2pkh_script(pubkey))
        assert len(coinbase_tx.vout[0].scriptPubKey) <= BTX_MAX_TXOUT_SCRIPT_SIZE
