#!/usr/bin/env python3
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A limited-functionality wallet, which may replace a real wallet in tests"""

from copy import deepcopy
from decimal import Decimal
from enum import Enum
import random
from typing import (
    Any,
    Optional,
)
from test_framework.address import (
    address_to_scriptpubkey,
    create_deterministic_address_bcrt1_p2tr_op_true,
    key_to_p2pkh,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
    merkle_root_to_p2mr,
    output_key_to_p2tr,
)
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.crypto.mldsa import MLDSA44Key
from test_framework.descriptors import descsum_create
from test_framework.key import (
    ECKey,
    compute_xonly_pubkey,
)
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    hash256,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_CHECKSIG_MLDSA,
    OP_NOP,
    OP_RETURN,
    OP_TRUE,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    P2MRSignatureHash,
    p2mr_single_leaf,
    sign_input_legacy,
    taproot_construct,
)
from test_framework.script_util import (
    key_to_p2pk_script,
    key_to_p2pkh_script,
    key_to_p2sh_p2wpkh_script,
    key_to_p2wpkh_script,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than_or_equal,
    get_fee,
)
from test_framework.wallet_util import generate_keypair

DEFAULT_FEE = Decimal("0.0001")

# vsize of a 1-in-1-out ADDRESS_P2MR self-transfer: 96 bytes of non-witness
# data plus the witness (2421-byte ML-DSA-44 signature with its sighash byte,
# 1316-byte leaf script, 1-byte control block). BTX has no witness discount.
P2MR_SELF_TRANSFER_VSIZE = 3842
# Same, spending one of the pre-mined P2TR OP_TRUE coins.
OP_TRUE_SELF_TRANSFER_VSIZE = 133


class MiniWalletMode(Enum):
    """Determines the transaction type the MiniWallet is creating and spending.

    BTX relays only P2MR (witness v2) and OP_RETURN outputs, so the default
    mode depends on the node the wallet is created for: ADDRESS_P2MR when the
    node enforces standardness, and ADDRESS_OP_TRUE when it was started with
    -acceptnonstdtxn=1.

    ADDRESS_P2MR pays to a fixed P2MR address whose single leaf is
    <ML-DSA-44 pubkey> OP_CHECKSIG_MLDSA. The framework signs each input with
    SIGHASH_NONE|SIGHASH_ANYONECANPAY, so a created transaction stays valid
    when the caller changes or adds outputs or adds inputs (but not when it
    changes the version, the locktime or a signed input). It can also spend the
    pre-mined ADDRESS_OP_TRUE coins of the test chain (spending them is
    standard, only creating them is not), so a fresh wallet has mature coins.
    Spends of its own outputs are large (P2MR_SELF_TRANSFER_VSIZE).

    ADDRESS_OP_TRUE uses a fixed bech32m P2TR address whose coins are spent
    with a witness stack of OP_TRUE, i.e. following an anyone-can-spend policy.
    However, if the transactions need to be modified by the user (e.g. prepending
    scriptSig for testing opcodes that are activated by a soft-fork), or the txs
    should contain an actual signature, the raw modes RAW_OP_TRUE, RAW_P2PK and
    RAW_P2PKH can be useful. In order to avoid mixing of UTXOs between different
    MiniWallet instances, a tag name can be passed to the address modes, to create
    different output scripts. Note that the UTXOs from the pre-generated test
    chain can only be spent if no tag is passed. Summary of modes:

                    |      output       |           |  tx is   | can modify |  needs
         mode       |    description    |  address  | standard | scriptSig  | signing
    ----------------+-------------------+-----------+----------+------------+----------
    ADDRESS_P2MR    | ML-DSA-44 leaf    |  bech32m  |   yes    |    no      |   yes
    ADDRESS_OP_TRUE | anyone-can-spend  |  bech32m  |   no     |    no      |   no
    RAW_OP_TRUE     | anyone-can-spend  |  - (raw)  |   no     |    yes     |   no
    RAW_P2PK        | pay-to-public-key |  - (raw)  |   no     |    yes     |   yes
    RAW_P2PKH       | pay-to-pubkey-hash|  - (raw)  |   no     |    yes     |   yes
    """
    ADDRESS_OP_TRUE = 1
    RAW_OP_TRUE = 2
    RAW_P2PK = 3
    RAW_P2PKH = 4
    ADDRESS_P2MR = 5


class MiniWallet:
    def __init__(self, test_node, *, mode=None, tag_name=None):
        self._test_node = test_node
        self._utxos = []
        if mode is None:
            mode = MiniWalletMode.ADDRESS_OP_TRUE if getattr(test_node, "accept_nonstd_txn", True) else MiniWalletMode.ADDRESS_P2MR
        self._mode = mode
        # ADDRESS_P2MR bookkeeping: values (in satoshis) of outpoints this
        # wallet has seen, and which of them are pre-mined OP_TRUE coins.
        self._outpoint_values = {}
        self._op_true_outpoints = set()
        self._op_true_script = None

        assert isinstance(mode, MiniWalletMode)
        if mode == MiniWalletMode.RAW_OP_TRUE:
            assert tag_name is None
            self._scriptPubKey = bytes(CScript([OP_TRUE]))
        elif mode in (MiniWalletMode.RAW_P2PK, MiniWalletMode.RAW_P2PKH):
            # use simple deterministic private key (k=1)
            assert tag_name is None
            self._priv_key = ECKey()
            self._priv_key.set((1).to_bytes(32, 'big'), True)
            pub_key = self._priv_key.get_pubkey()
            self._pub_key = pub_key.get_bytes()
            if mode == MiniWalletMode.RAW_P2PK:
                self._scriptPubKey = key_to_p2pk_script(self._pub_key)
            else:
                self._scriptPubKey = key_to_p2pkh_script(self._pub_key)
        elif mode == MiniWalletMode.ADDRESS_OP_TRUE:
            internal_key = None if tag_name is None else compute_xonly_pubkey(hash256(tag_name.encode()))[0]
            self._address, self._taproot_info = create_deterministic_address_bcrt1_p2tr_op_true(internal_key)
            self._scriptPubKey = address_to_scriptpubkey(self._address)
        elif mode == MiniWalletMode.ADDRESS_P2MR:
            self._p2mr_key = MLDSA44Key(hash256(b"MiniWallet ADDRESS_P2MR" + (tag_name or "").encode()))
            self._leaf_script = CScript([self._p2mr_key.pubkey, OP_CHECKSIG_MLDSA])
            self._scriptPubKey, self._control_block = p2mr_single_leaf(self._leaf_script)
            self._address = merkle_root_to_p2mr(self._scriptPubKey[2:])
            if tag_name is None:
                op_true_address, self._taproot_info = create_deterministic_address_bcrt1_p2tr_op_true()
                self._op_true_script = address_to_scriptpubkey(op_true_address)

        # When the pre-mined test framework chain is used, it contains coinbase
        # outputs to the MiniWallet's default address in blocks 76-100
        # (see method BitcoinTestFramework._initialize_chain())
        # The MiniWallet needs to rescan_utxos() in order to account
        # for those mature UTXOs, so that all txs spend confirmed coins
        self.rescan_utxos()

    def _create_utxo(self, *, txid, vout, value, height, coinbase, confirmations):
        self._outpoint_values[(txid, vout)] = int(value * COIN)
        return {"txid": txid, "vout": vout, "value": value, "height": height, "coinbase": coinbase, "confirmations": confirmations}

    def _bulk_tx(self, tx, target_vsize):
        """Pad a transaction with extra outputs until it reaches a target vsize.
        returns the tx
        """
        base_vsize = tx.get_vsize()
        if target_vsize < base_vsize:
            raise RuntimeError(f"target_vsize {target_vsize} is less than transaction virtual size {base_vsize}")

        def compact_size_len(n):
            if n < 253:
                return 1
            if n <= 0xffff:
                return 3
            if n <= 0xffffffff:
                return 5
            return 9

        needed = target_vsize - base_vsize
        if needed == 0:
            return

        # BTX consensus/policy rejects oversized scriptPubKeys and multiple
        # OP_RETURN outputs. Build padding with spendable outputs to our own
        # script plus at most one capped OP_RETURN output for fine-grained size.
        standard_script_size = len(self._scriptPubKey)
        standard_output_vbytes = 8 + compact_size_len(standard_script_size) + standard_script_size
        min_pad_output_value_sat = 1000
        initial_outputs = len(tx.vout)
        max_standard_outputs = tx.vout[0].nValue // min_pad_output_value_sat
        solution = None
        for standard_outputs in range(max_standard_outputs + 1):
            standard_contribution = standard_outputs * standard_output_vbytes
            for opreturn_script_size in range(84):
                add_opreturn = 1 if opreturn_script_size else 0
                opreturn_contribution = 0 if opreturn_script_size == 0 else 8 + compact_size_len(opreturn_script_size) + opreturn_script_size
                added_outputs = standard_outputs + add_opreturn
                varint_growth = compact_size_len(initial_outputs + added_outputs) - compact_size_len(initial_outputs)
                total_contribution = standard_contribution + opreturn_contribution + varint_growth
                if total_contribution == needed:
                    solution = (standard_outputs, opreturn_script_size)
                    break
            if solution is not None:
                break

        if solution is None:
            raise RuntimeError(f"Unable to pad transaction to target vsize {target_vsize}")

        standard_outputs, opreturn_script_size = solution
        if standard_outputs:
            tx.vout[0].nValue -= standard_outputs * min_pad_output_value_sat
            if tx.vout[0].nValue <= 0:
                raise RuntimeError(f"Unable to pad transaction to target vsize {target_vsize}")
            for _ in range(standard_outputs):
                tx.vout.append(CTxOut(nValue=min_pad_output_value_sat, scriptPubKey=bytearray(self._scriptPubKey)))

        if opreturn_script_size:
            tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([OP_RETURN] + [OP_1] * (opreturn_script_size - 1))))

        assert_equal(tx.get_vsize(), target_vsize)

    def get_balance(self):
        return sum(u['value'] for u in self._utxos)

    def rescan_utxos(self, *, include_mempool=True):
        """Drop all utxos and rescan the utxo set"""
        self._utxos = []
        scanobjects = [self.get_descriptor()]
        if self._op_true_script is not None:
            scanobjects.append(descsum_create(f'raw({self._op_true_script.hex()})'))
        res = self._test_node.scantxoutset(action="start", scanobjects=scanobjects)
        assert_equal(True, res['success'])
        for utxo in res['unspents']:
            if self._op_true_script is not None and utxo["scriptPubKey"] == self._op_true_script.hex():
                self._op_true_outpoints.add((utxo["txid"], utxo["vout"]))
            self._utxos.append(
                self._create_utxo(txid=utxo["txid"],
                                  vout=utxo["vout"],
                                  value=utxo["amount"],
                                  height=utxo["height"],
                                  coinbase=utxo["coinbase"],
                                  confirmations=res["height"] - utxo["height"] + 1))
        if include_mempool:
            mempool = self._test_node.getrawmempool(verbose=True)
            # Sort tx by ancestor count. See BlockAssembler::SortForBlock in src/node/miner.cpp
            sorted_mempool = sorted(mempool.items(), key=lambda item: (item[1]["ancestorcount"], int(item[0], 16)))
            for txid, _ in sorted_mempool:
                self.scan_tx(self._test_node.getrawtransaction(txid=txid, verbose=True))

    def scan_tx(self, tx):
        """Scan the tx and adjust the internal list of owned utxos"""
        for spent in tx["vin"]:
            # Mark spent. This may happen when the caller has ownership of a
            # utxo that remained in this wallet. For example, by passing
            # mark_as_spent=False to get_utxo or by using an utxo returned by a
            # create_self_transfer* call.
            try:
                self.get_utxo(txid=spent["txid"], vout=spent["vout"])
            except StopIteration:
                pass
        for out in tx['vout']:
            is_op_true = self._op_true_script is not None and out['scriptPubKey']['hex'] == self._op_true_script.hex()
            if out['scriptPubKey']['hex'] == self._scriptPubKey.hex() or is_op_true:
                if is_op_true:
                    self._op_true_outpoints.add((tx["txid"], out["n"]))
                self._utxos.append(self._create_utxo(txid=tx["txid"], vout=out["n"], value=out["value"], height=0, coinbase=False, confirmations=0))

    def scan_txs(self, txs):
        for tx in txs:
            self.scan_tx(tx)

    def sign_tx(self, tx, fixed_length=True):
        if self._mode == MiniWalletMode.RAW_P2PK:
            # for exact fee calculation, create only signatures with fixed size by default (>49.89% probability):
            # 65 bytes: high-R val (33 bytes) + low-S val (32 bytes)
            # with the DER header/skeleton data of 6 bytes added, plus 2 bytes scriptSig overhead
            # (OP_PUSHn and SIGHASH_ALL), this leads to a scriptSig target size of 73 bytes
            tx.vin[0].scriptSig = b''
            attempts = 0
            while len(tx.vin[0].scriptSig) != 73:
                tx.vin[0].scriptSig = b''
                sign_input_legacy(tx, 0, self._scriptPubKey, self._priv_key)
                if not fixed_length:
                    break
                attempts += 1
                if attempts > 512:
                    raise RuntimeError("Unable to construct fixed-length RAW_P2PK signature")
        elif self._mode == MiniWalletMode.RAW_P2PKH:
            # Legacy P2PKH needs [sig, pubkey] in scriptSig; keep high-R signatures
            # for deterministic vsize (192 vB for 1-in-1-out self-transfers).
            tx.vin[0].scriptSig = bytes(CScript([self._pub_key]))
            attempts = 0
            while len(tx.vin[0].scriptSig) != 107:
                tx.vin[0].scriptSig = bytes(CScript([self._pub_key]))
                sign_input_legacy(tx, 0, self._scriptPubKey, self._priv_key)
                if not fixed_length:
                    break
                attempts += 1
                if attempts > 512:
                    raise RuntimeError("Unable to construct fixed-length RAW_P2PKH signature")
        elif self._mode == MiniWalletMode.RAW_OP_TRUE:
            for i in tx.vin:
                i.scriptSig = CScript([OP_NOP] * 43)  # pad to identical size
        elif self._mode == MiniWalletMode.ADDRESS_OP_TRUE:
            tx.wit.vtxinwit = [CTxInWitness()] * len(tx.vin)
            for i in tx.wit.vtxinwit:
                assert_equal(len(self._taproot_info.leaves), 1)
                leaf_info = list(self._taproot_info.leaves.values())[0]
                i.scriptWitness.stack = [
                    leaf_info.script,
                    bytes([leaf_info.version | self._taproot_info.negflag]) + self._taproot_info.internal_pubkey,
                ]
        elif self._mode == MiniWalletMode.ADDRESS_P2MR:
            hash_type = SIGHASH_NONE | SIGHASH_ANYONECANPAY
            tx.wit.vtxinwit = [CTxInWitness() for _ in tx.vin]
            for index, (txin, wit) in enumerate(zip(tx.vin, tx.wit.vtxinwit)):
                outpoint = (f"{txin.prevout.hash:064x}", txin.prevout.n)
                if self._is_op_true_outpoint(outpoint):
                    leaf_info = list(self._taproot_info.leaves.values())[0]
                    wit.scriptWitness.stack = [
                        leaf_info.script,
                        bytes([leaf_info.version | self._taproot_info.negflag]) + self._taproot_info.internal_pubkey,
                    ]
                    continue
                # ANYONECANPAY commits to this input's own prevout only, so the
                # other entries of spent_utxos are never read.
                spent_utxos = [CTxOut() for _ in tx.vin]
                spent_utxos[index] = CTxOut(self._outpoint_value(outpoint), self._scriptPubKey)
                sighash = P2MRSignatureHash(tx, spent_utxos, hash_type, index, leaf_script=self._leaf_script)
                wit.scriptWitness.stack = [
                    self._p2mr_key.sign(sighash) + bytes([hash_type]),
                    bytes(self._leaf_script),
                    self._control_block,
                ]
        else:
            assert False

    def _is_op_true_outpoint(self, outpoint):
        """Whether an outpoint spent by this ADDRESS_P2MR wallet is a pre-mined OP_TRUE coin."""
        if self._op_true_script is None:
            return False
        if outpoint in self._op_true_outpoints:
            return True
        if outpoint in self._outpoint_values:
            return False
        txout = self._test_node.gettxout(txid=outpoint[0], n=outpoint[1], include_mempool=True)
        if txout is not None and txout["scriptPubKey"]["hex"] == self._op_true_script.hex():
            self._op_true_outpoints.add(outpoint)
            return True
        return False

    def _outpoint_value(self, outpoint):
        """Value in satoshis of an outpoint this ADDRESS_P2MR wallet signs for (P2MR sighashes commit to it)."""
        if outpoint not in self._outpoint_values:
            txout = self._test_node.gettxout(txid=outpoint[0], n=outpoint[1], include_mempool=True)
            assert txout is not None, f"MiniWallet ADDRESS_P2MR cannot sign for unknown outpoint {outpoint[0]}:{outpoint[1]}"
            self._outpoint_values[outpoint] = int(txout["value"] * COIN)
        return self._outpoint_values[outpoint]

    def generate(self, num_blocks, **kwargs):
        """Generate blocks with coinbase outputs to the internal address, and call rescan_utxos"""
        blocks = self._test_node.generatetodescriptor(num_blocks, self.get_descriptor(), **kwargs)
        # Calling rescan_utxos here makes sure that after a generate the utxo
        # set is in a clean state. For example, the wallet will update
        # - if the caller consumed utxos, but never used them
        # - if the caller sent a transaction that is not mined or got rbf'd
        # - after block re-orgs
        # - the utxo height for mined mempool txs
        # - However, the wallet will not consider remaining mempool txs
        self.rescan_utxos()
        return blocks

    def get_output_script(self):
        return self._scriptPubKey

    def get_descriptor(self):
        return descsum_create(f'raw({self._scriptPubKey.hex()})')

    def get_address(self):
        assert self._mode in (MiniWalletMode.ADDRESS_OP_TRUE, MiniWalletMode.ADDRESS_P2MR)
        return self._address

    def get_utxo(self, *, txid: str = '', vout: Optional[int] = None, mark_as_spent=True, confirmed_only=False) -> dict:
        """
        Returns a utxo and marks it as spent (pops it from the internal list)

        Args:
        txid: get the first utxo we find from a specific transaction
        """
        self._utxos = sorted(self._utxos, key=lambda k: (k['value'], -k['height']))  # Put the largest utxo last
        blocks_height = self._test_node.getblockchaininfo()['blocks']
        mature_coins = list(filter(lambda utxo: not utxo['coinbase'] or COINBASE_MATURITY - 1 <= blocks_height - utxo['height'], self._utxos))
        if txid:
            utxo_filter: Any = filter(lambda utxo: txid == utxo['txid'], self._utxos)
        else:
            utxo_filter = reversed(mature_coins)  # By default the largest utxo
        if vout is not None:
            utxo_filter = filter(lambda utxo: vout == utxo['vout'], utxo_filter)
        if confirmed_only:
            utxo_filter = filter(lambda utxo: utxo['confirmations'] > 0, utxo_filter)
        index = self._utxos.index(next(utxo_filter))
        if mark_as_spent:
            return self._utxos.pop(index)
        else:
            return self._utxos[index]

    def get_utxos(self, *, include_immature_coinbase=False, mark_as_spent=True, confirmed_only=False):
        """Returns the list of all utxos and optionally mark them as spent"""
        if not include_immature_coinbase:
            blocks_height = self._test_node.getblockchaininfo()['blocks']
            utxo_filter = filter(lambda utxo: not utxo['coinbase'] or COINBASE_MATURITY - 1 <= blocks_height - utxo['height'], self._utxos)
        else:
            utxo_filter = self._utxos
        if confirmed_only:
            utxo_filter = filter(lambda utxo: utxo['confirmations'] > 0, utxo_filter)
        utxos = deepcopy(list(utxo_filter))
        if mark_as_spent:
            self._utxos = []
        return utxos

    def send_self_transfer(self, *, from_node, **kwargs):
        """Call create_self_transfer and send the transaction."""
        tx = self.create_self_transfer(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx['hex'])
        return tx

    def send_to(self, *, from_node, scriptPubKey, amount, fee=1000):
        """
        Create and send a tx with an output to a given scriptPubKey/amount,
        plus a change output to our internal address. To keep things simple, a
        fixed fee given in Satoshi is used.

        Note that this method fails if there is no single internal utxo
        available that can cover the cost for the amount and the fixed fee
        (the utxo with the largest value is taken).
        """
        tx = self.create_self_transfer(fee_rate=0)["tx"]
        assert_greater_than_or_equal(tx.vout[0].nValue, amount + fee)
        tx.vout[0].nValue -= (amount + fee)           # change output -> MiniWallet
        tx.vout.append(CTxOut(amount, scriptPubKey))  # arbitrary output -> to be returned
        txid = self.sendrawtransaction(from_node=from_node, tx_hex=tx.serialize().hex())
        return {
            "sent_vout": 1,
            "txid": txid,
            "wtxid": tx.getwtxid(),
            "hex": tx.serialize().hex(),
            "tx": tx,
        }

    def send_self_transfer_multi(self, *, from_node, **kwargs):
        """Call create_self_transfer_multi and send the transaction."""
        tx = self.create_self_transfer_multi(**kwargs)
        self.sendrawtransaction(from_node=from_node, tx_hex=tx["hex"])
        return tx

    def create_self_transfer_multi(
        self,
        *,
        utxos_to_spend: Optional[list[dict]] = None,
        num_outputs=1,
        amount_per_output=0,
        version=2,
        locktime=0,
        sequence=0,
        fee_per_output=1000,
        target_vsize=0,
        confirmed_only=False,
    ):
        """
        Create and return a transaction that spends the given UTXOs and creates a
        certain number of outputs with equal amounts. The output amounts can be
        set by amount_per_output or automatically calculated with a fee_per_output.
        """
        utxos_to_spend = utxos_to_spend or [self.get_utxo(confirmed_only=confirmed_only)]
        sequence = [sequence] * len(utxos_to_spend) if type(sequence) is int else sequence
        assert_equal(len(utxos_to_spend), len(sequence))
        for utxo in utxos_to_spend:  # ADDRESS_P2MR signatures commit to the spent value
            outpoint = (utxo['txid'], utxo['vout'])
            if not self._is_op_true_outpoint(outpoint):
                self._outpoint_values.setdefault(outpoint, int(COIN * utxo['value']))

        # calculate output amount
        inputs_value_total = sum([int(COIN * utxo['value']) for utxo in utxos_to_spend])
        outputs_value_total = inputs_value_total - fee_per_output * num_outputs
        amount_per_output = amount_per_output or (outputs_value_total // num_outputs)
        assert amount_per_output > 0
        outputs_value_total = amount_per_output * num_outputs
        fee = Decimal(inputs_value_total - outputs_value_total) / COIN

        # create tx
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo_to_spend['txid'], 16), utxo_to_spend['vout']), nSequence=seq) for utxo_to_spend, seq in zip(utxos_to_spend, sequence)]
        tx.vout = [CTxOut(amount_per_output, bytearray(self._scriptPubKey)) for _ in range(num_outputs)]
        tx.version = version
        tx.nLockTime = locktime

        self.sign_tx(tx)

        if target_vsize:
            self._bulk_tx(tx, target_vsize)

        txid = tx.rehash()
        return {
            "new_utxos": [self._create_utxo(
                txid=txid,
                vout=i,
                value=Decimal(tx.vout[i].nValue) / COIN,
                height=0,
                coinbase=False,
                confirmations=0,
            ) for i in range(len(tx.vout))],
            "fee": fee,
            "txid": txid,
            "wtxid": tx.getwtxid(),
            "hex": tx.serialize().hex(),
            "tx": tx,
        }

    def create_self_transfer(
            self,
            *,
            fee_rate=Decimal("0.003"),
            fee=Decimal("0"),
            utxo_to_spend=None,
            target_vsize=0,
            confirmed_only=False,
            **kwargs,
    ):
        """Create and return a tx with the specified fee. If fee is 0, use fee_rate, where the resulting fee may be exact or at most one satoshi higher than needed."""
        utxo_to_spend = utxo_to_spend or self.get_utxo(confirmed_only=confirmed_only)
        assert fee_rate >= 0
        assert fee >= 0
        # calculate fee
        if self._mode == MiniWalletMode.RAW_OP_TRUE:
            vsize = Decimal(104)  # raw anyone-can-spend
        elif self._mode == MiniWalletMode.ADDRESS_OP_TRUE:
            # BTX has no witness discount (WITNESS_SCALE_FACTOR=1), so the
            # two witness framing bytes plus the 27-byte witness are counted.
            vsize = Decimal(OP_TRUE_SELF_TRANSFER_VSIZE)
        elif self._mode == MiniWalletMode.ADDRESS_P2MR:
            spends_op_true = self._is_op_true_outpoint((utxo_to_spend["txid"], utxo_to_spend["vout"]))
            vsize = Decimal(OP_TRUE_SELF_TRANSFER_VSIZE if spends_op_true else P2MR_SELF_TRANSFER_VSIZE)
        elif self._mode == MiniWalletMode.RAW_P2PK:
            vsize = Decimal(168)  # P2PK (73 bytes scriptSig + 35 bytes scriptPubKey + 60 bytes other)
        elif self._mode == MiniWalletMode.RAW_P2PKH:
            vsize = Decimal(192)  # P2PKH (107 bytes scriptSig + 25 bytes scriptPubKey + 60 bytes other)
        else:
            assert False
        if target_vsize and not fee:  # respect fee_rate if target vsize is passed
            fee = get_fee(target_vsize, fee_rate)
        send_value = utxo_to_spend["value"] - (fee or (fee_rate * vsize / 1000))
        if send_value <= 0:
            raise RuntimeError(f"UTXO value {utxo_to_spend['value']} is too small to cover fees {(fee or (fee_rate * vsize / 1000))}")
        # create tx
        tx = self.create_self_transfer_multi(
            utxos_to_spend=[utxo_to_spend],
            amount_per_output=int(COIN * send_value),
            target_vsize=target_vsize,
            **kwargs,
        )
        if not target_vsize:
            assert_equal(tx["tx"].get_vsize(), vsize)
        tx["new_utxo"] = tx.pop("new_utxos")[0]

        return tx

    def sendrawtransaction(self, *, from_node, tx_hex, maxfeerate=0, **kwargs):
        txid = from_node.sendrawtransaction(hexstring=tx_hex, maxfeerate=maxfeerate, **kwargs)
        self.scan_tx(from_node.decoderawtransaction(tx_hex))
        return txid

    def create_self_transfer_chain(self, *, chain_length, utxo_to_spend=None):
        """
        Create a "chain" of chain_length transactions. The nth transaction in
        the chain is a child of the n-1th transaction and parent of the n+1th transaction.
        """
        chaintip_utxo = utxo_to_spend or self.get_utxo()
        chain = []

        for _ in range(chain_length):
            tx = self.create_self_transfer(utxo_to_spend=chaintip_utxo)
            chaintip_utxo = tx["new_utxo"]
            chain.append(tx)

        return chain

    def send_self_transfer_chain(self, *, from_node, **kwargs):
        """Create and send a "chain" of chain_length transactions. The nth transaction in
        the chain is a child of the n-1th transaction and parent of the n+1th transaction.

        Returns a list of objects for each tx (see create_self_transfer_multi).
        """
        chain = self.create_self_transfer_chain(**kwargs)
        for t in chain:
            self.sendrawtransaction(from_node=from_node, tx_hex=t["hex"])
        return chain


def getnewdestination(address_type='p2mr'):
    """Generate a random destination of the specified type and return the
       corresponding public key, scriptPubKey and address. Supported types are
       'legacy', 'p2sh-segwit', 'bech32', 'bech32m' and 'p2mr' (the default:
       BTX relays only P2MR and OP_RETURN outputs). Can be used when a random
       destination is needed, but no compiled wallet is available (e.g. as
       replacement to the getnewaddress/getaddressinfo RPCs)."""
    if address_type == 'p2mr':
        pubkey = MLDSA44Key(random.randbytes(32)).pubkey
        scriptpubkey, _ = p2mr_single_leaf(CScript([pubkey, OP_CHECKSIG_MLDSA]))
        return pubkey, scriptpubkey, merkle_root_to_p2mr(scriptpubkey[2:])
    key, pubkey = generate_keypair()
    if address_type == 'legacy':
        scriptpubkey = key_to_p2pkh_script(pubkey)
        address = key_to_p2pkh(pubkey)
    elif address_type == 'p2sh-segwit':
        scriptpubkey = key_to_p2sh_p2wpkh_script(pubkey)
        address = key_to_p2sh_p2wpkh(pubkey)
    elif address_type == 'bech32':
        scriptpubkey = key_to_p2wpkh_script(pubkey)
        address = key_to_p2wpkh(pubkey)
    elif address_type == 'bech32m':
        tap = taproot_construct(compute_xonly_pubkey(key.get_bytes())[0])
        pubkey = tap.output_pubkey
        scriptpubkey = tap.scriptPubKey
        address = output_key_to_p2tr(pubkey)
    else:
        assert False
    return pubkey, scriptpubkey, address
