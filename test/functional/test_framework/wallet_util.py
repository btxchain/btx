#!/usr/bin/env python3
# Copyright (c) 2018-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Useful util functions for testing the wallet"""
from collections import namedtuple
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_framework.address import (
    byte_to_base58,
    key_to_p2pkh,
    key_to_p2sh_p2wpkh,
    key_to_p2wpkh,
    script_to_p2sh,
    script_to_p2sh_p2wsh,
    script_to_p2wsh,
)
from test_framework.key import ECKey
from test_framework.messages import (
    CTxIn,
    CTxInWitness,
    WITNESS_SCALE_FACTOR,
)
from test_framework.script_util import (
    key_to_p2pkh_script,
    key_to_p2wpkh_script,
    keys_to_multisig_script,
    script_to_p2sh_script,
    script_to_p2wsh_script,
)

Key = namedtuple('Key', ['privkey',
                         'pubkey',
                         'p2pkh_script',
                         'p2pkh_addr',
                         'p2wpkh_script',
                         'p2wpkh_addr',
                         'p2sh_p2wpkh_script',
                         'p2sh_p2wpkh_redeem_script',
                         'p2sh_p2wpkh_addr'])

Multisig = namedtuple('Multisig', ['privkeys',
                                   'pubkeys',
                                   'p2sh_script',
                                   'p2sh_addr',
                                   'redeem_script',
                                   'p2wsh_script',
                                   'p2wsh_addr',
                                   'p2sh_p2wsh_script',
                                   'p2sh_p2wsh_addr'])


def create_legacy_wallet_with_tool(test, node, wallet_name, *, blank=False, disable_private_keys=False, force_bdb=False, swap_bdb_endian=False):
    """Create a legacy wallet offline, without using the disabled createwallet path.

    Current BTX daemons deliberately reject ``createwallet(descriptors=false)``.
    Compatibility tests still need existing legacy wallets to exercise loading,
    importing, migration, and the offline wallet tool.  Build the fixture with
    btx-wallet while the target node is stopped, then let btxd load it normally.

    The tool's native legacy format is preserved unless ``force_bdb`` is
    requested by a test that specifically exercises Berkeley DB
    compatibility. This is SQLite when Berkeley DB support is unavailable.
    ``swap_bdb_endian`` selects the opposite-endian BDB format and verifies
    the resulting file header. ``blank`` and ``disable_private_keys`` are
    produced by filtering the
    tool-generated dump before restoring it.  This keeps all fixture material
    ephemeral and avoids checking private keys into the source tree.
    """
    assert not node.running
    assert not disable_private_keys or blank
    assert not swap_bdb_endian or force_bdb
    if wallet_name and (
        wallet_name in {".", ".."}
        or "/" in wallet_name
        or "\\" in wallet_name
        or wallet_name.startswith("__legacy_source_")
    ):
        raise AssertionError("legacy fixture wallet name must be one safe path component")

    wallet_dir = node.wallets_path
    wallet_dir.mkdir(parents=True, exist_ok=True)

    def run_tool(*args):
        command = [
            test.options.bitcoinwallet,
            f"-datadir={node.datadir_path}",
            f"-chain={test.chain}",
        ]
        command.extend(args)
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(
                f"btx-wallet failed ({result.returncode}): {' '.join(command[1:])}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

    # btx-wallet requires a nonempty wallet name. An unnamed legacy wallet is
    # restored under a temporary name and moved to the wallet-directory root.
    final_tool_name = wallet_name or "__legacy_unnamed_wallet"
    source_name = f"__legacy_source_{final_tool_name}"
    source_path = wallet_dir / source_name
    final_path = wallet_dir / final_tool_name
    unnamed_wallet_file = wallet_dir / "wallet.dat"
    assert not source_path.exists()
    assert not final_path.exists()
    if not wallet_name:
        assert not unnamed_wallet_file.exists()

    run_tool(f"-wallet={source_name}", "-legacy", "create")

    keypool_pubkeys = []
    with tempfile.TemporaryDirectory(dir=node.datadir_path, prefix="legacy-wallet-dump-") as temp_dir:
        dump_path = Path(temp_dir) / "wallet.dump"
        run_tool(f"-wallet={source_name}", f"-dumpfile={dump_path}", "dump")

        with open(dump_path, encoding="utf8") as dump_file:
            lines = dump_file.readlines()
        for line in lines:
            key, separator, value_hex = line.strip().partition(',')
            if not separator or not key.startswith("04706f6f6c"):  # "pool" + int64 index
                continue
            value = bytes.fromhex(value_hex)
            # CKeyPool: int32 version, int64 timestamp, compact-size pubkey.
            pubkey_size = value[12]
            if pubkey_size in (33, 65):
                keypool_pubkeys.append(value[13:13 + pubkey_size].hex())

        if blank:
            # A minimal blank wallet needs only its format/version records and
            # mandatory wallet flags. The dump checksum covers every preceding
            # byte and is recomputed after filtering.
            flags_key = "05666c616773"
            preserved_keys = {
                "0776657273696f6e",      # version
                "0a6d696e76657273696f6e",  # minversion
                flags_key,
            }
            body = lines[:2]
            for line in lines[2:]:
                key = line.partition(',')[0]
                if key in preserved_keys and key != "checksum":
                    body.append(line)

            flags = (1 << 33) | ((1 << 32) if disable_private_keys else 0)
            flags_line = f"{flags_key},{flags.to_bytes(8, 'little').hex()}\n"
            body = [line for line in body if not line.startswith(f"{flags_key},")]
            body.append(flags_line)
            checksum = hashlib.sha256(hashlib.sha256(''.join(body).encode()).digest()).hexdigest()
            with open(dump_path, 'w', encoding="utf8") as dump_file:
                dump_file.writelines(body)
                dump_file.write(f"checksum,{checksum}\n")

        shutil.rmtree(source_path)
        restore_args = [f"-wallet={final_tool_name}", f"-dumpfile={dump_path}"]
        if force_bdb:
            restore_args.append(f"-format={'bdb_swap' if swap_bdb_endian else 'bdb'}")
        run_tool(*restore_args, "createfromdump")

    if swap_bdb_endian:
        with open(final_path / "wallet.dat", "rb") as wallet_file:
            wallet_file.seek(12)
            magic = wallet_file.read(4)
        assert magic == (0x62310500).to_bytes(4, byteorder=sys.byteorder)

    if not wallet_name:
        shutil.move(final_path / "wallet.dat", unnamed_wallet_file)
        # Berkeley DB leaves its environment log and lock alongside wallet.dat.
        # They belong to the temporary named restore, not to the unnamed wallet
        # fixture, and make a plain rmdir() fail even after wallet.dat is moved.
        shutil.rmtree(final_path)

    return keypool_pubkeys

def get_key(node):
    """Generate a fresh key on node

    Returns a named tuple of privkey, pubkey and all address and scripts."""
    addr = node.getnewaddress()
    pubkey = node.getaddressinfo(addr)['pubkey']
    return Key(privkey=node.dumpprivkey(addr),
               pubkey=pubkey,
               p2pkh_script=key_to_p2pkh_script(pubkey).hex(),
               p2pkh_addr=key_to_p2pkh(pubkey),
               p2wpkh_script=key_to_p2wpkh_script(pubkey).hex(),
               p2wpkh_addr=key_to_p2wpkh(pubkey),
               p2sh_p2wpkh_script=script_to_p2sh_script(key_to_p2wpkh_script(pubkey)).hex(),
               p2sh_p2wpkh_redeem_script=key_to_p2wpkh_script(pubkey).hex(),
               p2sh_p2wpkh_addr=key_to_p2sh_p2wpkh(pubkey))

def get_generate_key():
    """Generate a fresh key

    Returns a named tuple of privkey, pubkey and all address and scripts."""
    privkey, pubkey = generate_keypair(wif=True)
    return Key(privkey=privkey,
               pubkey=pubkey.hex(),
               p2pkh_script=key_to_p2pkh_script(pubkey).hex(),
               p2pkh_addr=key_to_p2pkh(pubkey),
               p2wpkh_script=key_to_p2wpkh_script(pubkey).hex(),
               p2wpkh_addr=key_to_p2wpkh(pubkey),
               p2sh_p2wpkh_script=script_to_p2sh_script(key_to_p2wpkh_script(pubkey)).hex(),
               p2sh_p2wpkh_redeem_script=key_to_p2wpkh_script(pubkey).hex(),
               p2sh_p2wpkh_addr=key_to_p2sh_p2wpkh(pubkey))

def get_multisig(node):
    """Generate a fresh 2-of-3 multisig on node

    Returns a named tuple of privkeys, pubkeys and all address and scripts."""
    addrs = []
    pubkeys = []
    for _ in range(3):
        addr = node.getaddressinfo(node.getnewaddress())
        addrs.append(addr['address'])
        pubkeys.append(addr['pubkey'])
    script_code = keys_to_multisig_script(pubkeys, k=2)
    witness_script = script_to_p2wsh_script(script_code)
    return Multisig(privkeys=[node.dumpprivkey(addr) for addr in addrs],
                    pubkeys=pubkeys,
                    p2sh_script=script_to_p2sh_script(script_code).hex(),
                    p2sh_addr=script_to_p2sh(script_code),
                    redeem_script=script_code.hex(),
                    p2wsh_script=witness_script.hex(),
                    p2wsh_addr=script_to_p2wsh(script_code),
                    p2sh_p2wsh_script=script_to_p2sh_script(witness_script).hex(),
                    p2sh_p2wsh_addr=script_to_p2sh_p2wsh(script_code))

def test_address(node, address, **kwargs):
    """Get address info for `address` and test whether the returned values are as expected."""
    addr_info = node.getaddressinfo(address)
    for key, value in kwargs.items():
        if value is None:
            if key in addr_info.keys():
                raise AssertionError("key {} unexpectedly returned in getaddressinfo.".format(key))
        elif addr_info[key] != value:
            raise AssertionError("key {} value {} did not match expected value {}".format(key, addr_info[key], value))

def bytes_to_wif(b, compressed=True):
    if compressed:
        b += b'\x01'
    return byte_to_base58(b, 239)

def generate_keypair(compressed=True, wif=False):
    """Generate a new random keypair and return the corresponding ECKey /
    bytes objects. The private key can also be provided as WIF (wallet
    import format) string instead, which is often useful for wallet RPC
    interaction."""
    privkey = ECKey()
    privkey.generate(compressed)
    pubkey = privkey.get_pubkey().get_bytes()
    if wif:
        privkey = bytes_to_wif(privkey.get_bytes(), compressed)
    return privkey, pubkey

def calculate_input_weight(scriptsig_hex, witness_stack_hex=None):
    """Given a scriptSig and a list of witness stack items for an input in hex format,
       calculate the total input weight. If the input has no witness data,
       `witness_stack_hex` can be set to None."""
    tx_in = CTxIn(scriptSig=bytes.fromhex(scriptsig_hex))
    witness_size = 0
    if witness_stack_hex is not None:
        tx_inwit = CTxInWitness()
        for witness_item_hex in witness_stack_hex:
            tx_inwit.scriptWitness.stack.append(bytes.fromhex(witness_item_hex))
        witness_size = len(tx_inwit.serialize())
    return len(tx_in.serialize()) * WITNESS_SCALE_FACTOR + witness_size

class WalletUnlock():
    """
    A context manager for unlocking a wallet with a passphrase and automatically locking it afterward.
    """

    MAXIMUM_TIMEOUT = 999000

    def __init__(self, wallet, passphrase, timeout=MAXIMUM_TIMEOUT):
        self.wallet = wallet
        self.passphrase = passphrase
        self.timeout = timeout

    def __enter__(self):
        self.wallet.walletpassphrase(self.passphrase, self.timeout)

    def __exit__(self, *args):
        _ = args
        self.wallet.walletlock()


class TestFrameworkWalletUtil(unittest.TestCase):
    def test_calculate_input_weight(self):
        SKELETON_BYTES = 32 + 4 + 4  # prevout-txid, prevout-index, sequence
        SMALL_LEN_BYTES = 1  # bytes needed for encoding scriptSig / witness item lengths < 253
        LARGE_LEN_BYTES = 3  # bytes needed for encoding scriptSig / witness item lengths >= 253

        # empty scriptSig, no witness
        self.assertEqual(calculate_input_weight(""),
                         (SKELETON_BYTES + SMALL_LEN_BYTES) * WITNESS_SCALE_FACTOR)
        self.assertEqual(calculate_input_weight("", None),
                         (SKELETON_BYTES + SMALL_LEN_BYTES) * WITNESS_SCALE_FACTOR)
        # small scriptSig, no witness
        scriptSig_small = "00"*252
        self.assertEqual(calculate_input_weight(scriptSig_small, None),
                         (SKELETON_BYTES + SMALL_LEN_BYTES + 252) * WITNESS_SCALE_FACTOR)
        # small scriptSig, empty witness stack
        self.assertEqual(calculate_input_weight(scriptSig_small, []),
                         (SKELETON_BYTES + SMALL_LEN_BYTES + 252) * WITNESS_SCALE_FACTOR + SMALL_LEN_BYTES)
        # large scriptSig, no witness
        scriptSig_large = "00"*253
        self.assertEqual(calculate_input_weight(scriptSig_large, None),
                         (SKELETON_BYTES + LARGE_LEN_BYTES + 253) * WITNESS_SCALE_FACTOR)
        # large scriptSig, empty witness stack
        self.assertEqual(calculate_input_weight(scriptSig_large, []),
                         (SKELETON_BYTES + LARGE_LEN_BYTES + 253) * WITNESS_SCALE_FACTOR + SMALL_LEN_BYTES)
        # empty scriptSig, 5 small witness stack items
        self.assertEqual(calculate_input_weight("", ["00", "11", "22", "33", "44"]),
                         ((SKELETON_BYTES + SMALL_LEN_BYTES) * WITNESS_SCALE_FACTOR) + SMALL_LEN_BYTES + 5 * SMALL_LEN_BYTES + 5)
        # empty scriptSig, 253 small witness stack items
        self.assertEqual(calculate_input_weight("", ["00"]*253),
                         ((SKELETON_BYTES + SMALL_LEN_BYTES) * WITNESS_SCALE_FACTOR) + LARGE_LEN_BYTES + 253 * SMALL_LEN_BYTES + 253)
        # small scriptSig, 3 large witness stack items
        self.assertEqual(calculate_input_weight(scriptSig_small, ["00"*253]*3),
                         ((SKELETON_BYTES + SMALL_LEN_BYTES + 252) * WITNESS_SCALE_FACTOR) + SMALL_LEN_BYTES + 3 * LARGE_LEN_BYTES + 3*253)
        # large scriptSig, 3 large witness stack items
        self.assertEqual(calculate_input_weight(scriptSig_large, ["00"*253]*3),
                         ((SKELETON_BYTES + LARGE_LEN_BYTES + 253) * WITNESS_SCALE_FACTOR) + SMALL_LEN_BYTES + 3 * LARGE_LEN_BYTES + 3*253)
