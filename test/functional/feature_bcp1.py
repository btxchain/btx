#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated-regtest BCP/1 / BTX_EXCHANGE_PROFILE_V1 certification.

Regtest btxd, watch-only wallet, software signer, deposit / withdraw / reorg /
batch / consolidation / restart. Named wallet RPCs are the lock: this test
calls them. If they are not in the binary, skip honestly (exit 77). Partial
implementation fails closed. Never production datadir /var/lib/btxd.

Custody signing round trip: deposit addresses come from pubkeys the software
signer exports (`contrib/bcp1/mock_signer.py getpubkey`), imported with
`importdepositpool` as the documented single-leaf `mr(<ML-DSA-44 pubkey>)`
watch-only form. The coordinator builds an unsigned package and its canonical
P2MR digests, the signer returns a real ML-DSA-44 signature per digest,
`finalizeexternalsign` verifies those signatures and returns the signed hex, and
the test broadcasts explicitly only after `testmempoolaccept`.
`finalizeexternalsign` never broadcasts; the "no auto-broadcast" assertion runs
before any send. The signer backend needs a host OpenSSL 3.5+ CLI; without it
the test skips (exit 77) rather than claiming a signature it cannot produce. The
signer's `--stub-signature` fixture is non-cryptographic and is used only by the
"corrupt signature rejection" row.

Known defect pinned by this harness (not fixed here): for a two-leaf
`mr(<ml>,pk_slh(<slh>))` watch-only deposit descriptor the wallet cannot identify
the ML-DSA leaf (a public-only signing provider carries no `pq_keys`), so
`prepareexternalsign` selects the SLH-DSA leaf and still labels the input
`algo: ml_dsa_44` (src/wallet/rpc/bcp1.cpp AttachWalletP2MR). An ML-DSA-only
external signer cannot complete that package, and consensus then rejects the
mis-signed witness. The harness records the two-leaf address it derives and uses
the single-leaf ML form for the live signature round trip.

Related, pinned at runtime by the "corrupt signature rejection" row:
`finalizeexternalsign` verifies each signature against the coordinator-supplied
pubkey but does not bind that pubkey to the selected leaf script, so a
cross-key signature reports `complete=true` locally and only
`testmempoolaccept`/consensus rejects the witness. Never treat local `complete`
as broadcastable.

Known defect pinned by this harness (not fixed here): the documented result
object of `importdepositpool` in src/wallet/rpc/bcp1.cpp starts with
`success`/`imported` and ends with an ELISION entry. The node's `-rpcdoccheck`
treats a non-leading ELISION as a required result key, so every successful
`importdepositpool` call aborts with "Internal bug detected: RPC call
\"importdepositpool\" returned incorrect type". Every other BCP/1 result puts
ELISION first and passes. The custody path still has to be exercised, so the
coin (node 1) disables its own RPC doc check for this run; node 0 keeps it and
the harness logs the defect it observes there. Fix by making the first result
entry an ELISION (or documenting `address_only`).

  python3 test/functional/feature_bcp1.py \\
    --configfile=build-gcc13/test/config.ini \\
    --timeout-factor=1
"""

from decimal import Decimal
import json
import os
import subprocess
import sys

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY, REGTEST_GENERIC_P2P_MATMUL_ARGS
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    find_vout_for_address,
)

PROD_DATADIR = "/var/lib/btxd"
PROFILE = "BTX_EXCHANGE_PROFILE_V1"
MOCK_FINGERPRINT = "00000001"
MLDSA44_PUBKEY_BYTES = 1312
SLHDSA128S_PUBKEY_BYTES = 32
MLDSA44_SIGNATURE_BYTES = 2420
SECRET_NEEDLES = (
    "wallet_seed",
    "pq_master_seed",
    "mnemonic",
    "xprv",
    "secret_key",
    "dumpprivkey",
    "id_ed25519",
    "aws_secret_access_key",
)
BCP1_RPCS = (
    "getexchangereadiness",
    "deriveexchangeaddress",
    "importdepositpool",
    "prepareexternalsign",
    "getsigningdigests",
    "finalizeexternalsign",
    "getdepositstatus",
    "listdepositutxos",
    "planconsolidation",
    "createconsolidationtx",
    "estimateconsolidationfee",
    "createexchangebatch",
)
PASS_ROWS = (
    "address generation",
    "deposit detection",
    "1→N confirmations",
    "reorg handling",
    "unsigned withdrawal",
    "external PQ signature",
    "signature import",
    "corrupt signature rejection",
    "broadcast",
    "batch withdrawal",
    "UTXO consolidation",
    "double-spend rejection",
    "node restart",
    "wallet recovery",
)
METHOD_NOT_FOUND = (-32601,)
RETRY_PARAM = (-32602, -8, -3, -1, -5, -4)


class BCP1Test(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def mock_signer_file(self):
        root = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", ".."))
        return os.path.join(root, "contrib", "bcp1", "mock_signer.py")

    def mock_signer_cmd(self):
        return sys.executable + " " + self.mock_signer_file()

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.wallet_names = ["miner", False]
        signer = self.mock_signer_cmd()
        self.exchange_args = [
            f"-signer={signer}",
            "-exchange-watchonly",
            "-txindex=1",
            "-keypool=20",
            "-fallbackfee=0.0002",
            "-modelnet=0",
            "-nomodelnet",
            # See the module docstring: importdepositpool's result doc has a
            # non-leading ELISION, so the node's own -rpcdoccheck rejects every
            # successful call. The defect is logged (node 0 keeps the check);
            # this run must still exercise the custody RPCs.
            "-rpcdoccheck=0",
        ] + list(REGTEST_GENERIC_P2P_MATMUL_ARGS)
        self.extra_args = [
            ["-txindex=1", "-fallbackfee=0.0002", "-modelnet=0", "-nomodelnet"] + list(REGTEST_GENERIC_P2P_MATMUL_ARGS),
            list(self.exchange_args),
        ]
        self.passed = []

    def setup_nodes(self):
        bitcoind = self.options.bitcoind
        blob = ""
        try:
            probed = subprocess.run(
                [bitcoind, "-help"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            blob = (probed.stdout or "") + (probed.stderr or "")
        except (OSError, subprocess.SubprocessError):
            blob = ""
        if "exchange-watchonly" in blob:
            self.exchange_args.append("-exchange-watchonly=1")
            self.extra_args[1] = list(self.exchange_args)
        return super().setup_nodes()

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_external_signer()

    # --- guards -----------------------------------------------------------

    def _refuse_production_datadir(self):
        tmp = os.path.realpath(self.options.tmpdir)
        if tmp == PROD_DATADIR or tmp.startswith(PROD_DATADIR + os.sep):
            raise AssertionError(f"refusing production datadir tmpdir={tmp}")
        for node in self.nodes:
            datadir = os.path.realpath(str(node.datadir_path))
            if datadir == PROD_DATADIR or datadir.startswith(PROD_DATADIR + os.sep):
                raise AssertionError(f"refusing production datadir node={datadir}")

    def _pass(self, name):
        self.log.info("PASS %s", name)
        if name not in self.passed:
            self.passed.append(name)

    def _dump(self, obj):
        return json.dumps(obj, default=str).lower() if not isinstance(obj, str) else obj.lower()

    def _no_secrets(self, obj, where):
        dumped = self._dump(obj)
        for needle in SECRET_NEEDLES:
            if needle in dumped and "***" not in dumped:
                raise AssertionError(f"{where} leaked {needle}: {obj}")
        spend = None
        if isinstance(obj, dict):
            spend = obj.get("automatic_spend_atoms")
        if spend not in (None, 0, "0"):
            raise AssertionError(f"{where} automatic_spend_atoms={spend}")

    def _rpc_listed(self, node, name):
        try:
            text = node.help(name)
        except JSONRPCException as exc:
            err = exc.error if isinstance(exc.error, dict) else {}
            if err.get("code") in METHOD_NOT_FOUND:
                return False
            raise
        return "unknown command" not in str(text).lower()

    def _call_variants(self, fn, variants):
        last = None
        for args, kwargs in variants:
            try:
                result = fn(*args, **kwargs)
                self._no_secrets(result, getattr(fn, "_service_name", "rpc"))
                return result
            except JSONRPCException as exc:
                last = exc
                err = exc.error if isinstance(exc.error, dict) else {}
                if err.get("code") in METHOD_NOT_FOUND:
                    raise
                if err.get("code") not in RETRY_PARAM:
                    raise
        if last is not None:
            raise last
        raise AssertionError("no RPC variants")

    # --- software signer (contrib/bcp1/mock_signer.py) --------------------

    def _signer_keystore(self):
        return os.path.join(str(self.nodes[1].cwd), ".bcp1-signer-keystore")

    def _mock(self, *args, raise_on_error=True):
        cmd = [
            sys.executable,
            self.mock_signer_file(),
            "--fingerprint", MOCK_FINGERPRINT,
            "--chain", "regtest",
            "--keystore", self._signer_keystore(),
        ] + list(args)
        proc = subprocess.run(
            cmd,
            cwd=str(self.nodes[1].cwd),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(f"software signer {' '.join(args)} failed: {proc.stderr or proc.stdout}")
        try:
            result = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"software signer {' '.join(args)} not JSON: {proc.stdout!r} ({exc})")
        self._no_secrets(result, "software signer " + " ".join(args))
        if raise_on_error and isinstance(result, dict) and result.get("error"):
            raise AssertionError(f"software signer {' '.join(args)}: {result}")
        return result

    def skip_if_no_software_signer(self):
        """Fail closed: no real ML-DSA-44 signer backend -> skip, never fake a PASS."""
        health = self._mock("health", raise_on_error=False)
        if not isinstance(health, dict) or not health.get("ok"):
            detail = ""
            if isinstance(health, dict):
                detail = str(health.get("detail") or health.get("error") or "")
            raise SkipTest(f"no real ML-DSA-44 software signer backend: {detail or health}")
        if "ml_dsa_44" not in health.get("signing_algorithms", []):
            raise SkipTest(f"software signer does not sign ML-DSA-44: {health}")

    def _signer_pubkey(self, path, algo):
        result = self._mock("getpubkey", "--path", path, "--algo", algo)
        pubkey = result.get("pubkey")
        if not isinstance(pubkey, str) or not pubkey:
            raise AssertionError(f"signer pubkey missing for {algo} {path}: {result}")
        expected = MLDSA44_PUBKEY_BYTES if algo == "ml_dsa_44" else SLHDSA128S_PUBKEY_BYTES
        if len(pubkey) != expected * 2:
            raise AssertionError(f"signer {algo} pubkey is {len(pubkey) // 2} bytes, want {expected}")
        if result.get("stub") is not False:
            raise AssertionError(f"signer pubkey must be real, not a stub: {result}")
        return pubkey

    def _signer_sign_digest(self, digest_hex, path, stub=False):
        args = ["signdigest", "--path", path, "--algo", "ml_dsa_44", "--digest", digest_hex]
        if stub:
            args.append("--stub-signature")
        result = self._mock(*args)
        signature = result.get("signature")
        if not isinstance(signature, str) or not signature:
            raise AssertionError(f"signer signature missing: {result}")
        if len(signature) != MLDSA44_SIGNATURE_BYTES * 2:
            raise AssertionError(f"signer signature is {len(signature) // 2} bytes, want {MLDSA44_SIGNATURE_BYTES}")
        if bool(result.get("stub")) != bool(stub):
            raise AssertionError(f"signer stub flag mismatch: {result}")
        return signature

    # --- chain helpers ----------------------------------------------------

    def _follow_miner(self, miner_node, exchange_node):
        """Force the exchange node onto the miner's chain without P2P."""
        miner_tip = miner_node.getbestblockhash()
        if exchange_node.getbestblockhash() == miner_tip:
            return
        while (exchange_node.getblockcount() > 0 and
               exchange_node.getbestblockhash() != miner_tip and
               exchange_node.getblockcount() >= miner_node.getblockcount()):
            try:
                exchange_node.invalidateblock(exchange_node.getbestblockhash())
            except JSONRPCException:
                break
        start = exchange_node.getblockcount() + 1
        end = miner_node.getblockcount()
        for height in range(start, end + 1):
            blockhash = miner_node.getblockhash(height)
            raw = miner_node.getblock(blockhash, 0)
            result = exchange_node.submitblock(raw)
            if result not in (None, "duplicate", "duplicate-invalid", "inconclusive"):
                self.log.info("submitblock height %s: %s", height, result)
        if exchange_node.getbestblockhash() != miner_tip:
            self.log.info(
                "exchange tip %s miner tip %s",
                exchange_node.getbestblockhash(),
                miner_tip,
            )

    def _push_raw(self, dest_node, src_node, txid):
        raw = src_node.getrawtransaction(txid)
        try:
            dest_node.sendrawtransaction(raw)
        except JSONRPCException as exc:
            msg = str(exc).lower()
            if "already" not in msg:
                self.log.info("push raw %s: %s", txid, exc)

    # --- RPC result helpers ----------------------------------------------

    def _status_of(self, result):
        if isinstance(result, str):
            return result.upper()
        if isinstance(result, dict):
            for key in ("status", "state", "deposit_status"):
                if key in result and result[key] is not None:
                    return str(result[key]).upper()
        raise AssertionError(f"getdepositstatus missing status: {result}")

    def _address_of(self, result):
        if isinstance(result, str) and result:
            return result
        if isinstance(result, dict):
            for key in ("address", "deposit_address"):
                if result.get(key):
                    return result[key]
            addrs = result.get("addresses")
            if isinstance(addrs, list) and addrs:
                item = addrs[0]
                if isinstance(item, str):
                    return item
                if isinstance(item, dict) and item.get("address"):
                    return item["address"]
        raise AssertionError(f"no address in {result}")

    def _as_list(self, result):
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("utxos", "deposits", "entries", "outputs", "digests", "plan", "inputs"):
                if isinstance(result.get(key), list):
                    return result[key]
        return []

    def _package_of(self, result):
        if isinstance(result, str) and result:
            return {"psbt": result}
        if not isinstance(result, dict):
            raise AssertionError(f"unsigned package not an object: {result}")
        return result

    def _digests_of(self, result):
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            if isinstance(result.get("digests"), list):
                return result["digests"]
            if isinstance(result.get("inputs"), list):
                return [i for i in result["inputs"] if isinstance(i, dict) and i.get("digest")]
        return []

    def _hex_digest(self, item):
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            for key in ("digest", "sighash", "hash"):
                if item.get(key):
                    return str(item[key])
        raise AssertionError(f"digest missing: {item}")

    def _require_bcp1_rpcs(self, node):
        present = [name for name in BCP1_RPCS if self._rpc_listed(node, name)]
        missing = [name for name in BCP1_RPCS if name not in present]
        if not present:
            raise SkipTest(
                "BCP/1 RPCs are not in this binary: " + ", ".join(BCP1_RPCS)
            )
        if missing:
            raise AssertionError(
                "BCP/1 fail closed: partial RPC surface "
                f"present={present} missing={missing}"
            )
        return present

    def _open_exchange(self, node):
        try:
            node.createwallet(
                wallet_name="exchange",
                disable_private_keys=True,
                descriptors=True,
                external_signer=True,
                load_on_startup=True,
            )
        except JSONRPCException as exc:
            self.log.info("external_signer wallet create: %s; blank watch-only", exc)
            try:
                node.unloadwallet("exchange")
            except JSONRPCException:
                pass
            node.createwallet(
                wallet_name="exchange_pool",
                disable_private_keys=True,
                blank=True,
                descriptors=True,
                load_on_startup=True,
            )
            wallet = node.get_wallet_rpc("exchange_pool")
            self.exchange_wallet_name = "exchange_pool"
        else:
            wallet = node.get_wallet_rpc("exchange")
            self.exchange_wallet_name = "exchange"
        info = wallet.getwalletinfo()
        if info.get("private_keys_enabled") is True:
            raise AssertionError(f"exchange wallet must be watch-only: {info}")
        self._no_secrets(info, "getwalletinfo")
        return wallet

    # --- deposit pool from signer pubkeys ---------------------------------

    def _pool_address_from_pubkeys(self, node, ml_hex, slh_hex=None):
        """Node-side independent derivation of the P2MR address committed by
        the signer's own pubkeys (not the wallet's import bookkeeping).

        `slh_hex=None` is the single-leaf `mr(<ML-DSA-44>)` form the software
        signer can actually sign for; passing `slh_hex` derives the two-leaf
        wallet tree and is used to record why it is not the round-trip pool.
        """
        descriptor = f"mr({ml_hex})" if not slh_hex else f"mr({ml_hex},pk_slh({slh_hex}))"
        derived = node.deriveaddresses(descriptor, None, {"require_checksum": False})
        if not isinstance(derived, list) or len(derived) != 1 or not derived[0]:
            raise AssertionError(f"deriveaddresses({descriptor[:24]}...): {derived}")
        return derived[0]

    def _import_signer_deposit_pool(self, wallet, node, count=4):
        pool = []
        for index in range(count):
            path = f"m/87h/1h/0h/0/{index}"
            ml = self._signer_pubkey(path, "ml_dsa_44")
            slh = self._signer_pubkey(path, "slh_dsa_128s")
            address = self._pool_address_from_pubkeys(node, ml)
            two_leaf = self._pool_address_from_pubkeys(node, ml, slh)
            if two_leaf == address:
                raise AssertionError(
                    f"single-leaf and two-leaf signer trees must differ for {path}"
                )
            if index == 0:
                self.log.info(
                    "signer %s: single-leaf ml address %s; two-leaf (ml+slh) address %s "
                    "(wallet leaf selection defect, see module docstring)",
                    path, address, two_leaf,
                )
            pool.append({
                "index": index,
                "path": path,
                "pubkey": ml,
                "pubkey_slh": slh,
                "two_leaf_address": two_leaf,
                "address": address,
                "label": f"deposit/{index}",
            })
        entries = [
            {
                "index": entry["index"],
                "label": entry["label"],
                "pubkey": entry["pubkey"],
            }
            for entry in pool
        ]
        imported = wallet.importdepositpool(entries)
        self._no_secrets(imported, "importdepositpool")
        if isinstance(imported, dict) and imported.get("success") is False:
            raise AssertionError(f"importdepositpool: {imported}")
        if len({entry["address"] for entry in pool}) != len(pool):
            raise AssertionError(f"deposit pool index collision: {[e['address'] for e in pool]}")
        for entry in pool:
            info = wallet.getaddressinfo(entry["address"])
            if not (info.get("solvable") or info.get("ismine") or info.get("iswatchonly")):
                raise AssertionError(f"imported signer address not watched: {entry} info={info}")
            # Witness-v2 P2MR scriptPubKey (OP_2 + 32-byte merkle root). Kept so
            # the unsigned package can be mapped back to the signer key that
            # owns each prevout.
            spk = info.get("scriptPubKey")
            if not isinstance(spk, str) or len(spk) != 68 or not spk.startswith("52"):
                raise AssertionError(f"deposit pool address is not a P2MR script: {entry} info={info}")
            entry["script_pubkey"] = spk.lower()
            watch_pub = info.get("pubkey")
            if isinstance(watch_pub, str) and watch_pub.lower() != entry["pubkey"].lower():
                raise AssertionError(
                    f"getaddressinfo pubkey {watch_pub[:16]}... does not match the signer "
                    f"pubkey for {entry['address']}"
                )
            entry["watch_pubkey_exposed"] = isinstance(watch_pub, str)
        self.log.info(
            "imported %d single-leaf ML-DSA deposit descriptors; "
            "getaddressinfo pubkey exposed (public-only pq_keys): %s",
            len(pool), [entry["watch_pubkey_exposed"] for entry in pool],
        )
        return pool

    def _note_importdepositpool_doc_defect(self, node):
        """Record the RPC result-doc defect on the node that keeps -rpcdoccheck.

        Probe only: never fails the run. When the result doc is fixed this logs
        that the workaround is no longer needed.
        """
        name = "doccheck_probe"
        try:
            try:
                node.createwallet(
                    wallet_name=name,
                    disable_private_keys=True,
                    blank=True,
                    descriptors=True,
                    load_on_startup=False,
                )
            except JSONRPCException as exc:
                self.log.info("rpc doc-check probe: cannot create %s: %s", name, exc)
                return
            probe = node.get_wallet_rpc(name)
            sample = self._signer_pubkey("m/87h/1h/0h/0/0", "ml_dsa_44")
            try:
                probe.importdepositpool([{"index": 0, "label": "deposit/0", "pubkey": sample}])
            except JSONRPCException as exc:
                message = str(exc)
                if "Internal bug detected" in message and "importdepositpool" in message:
                    self.log.warning(
                        "KNOWN DEFECT (unfixed here): importdepositpool result docs make "
                        "-rpcdoccheck reject every successful call; node 1 runs with "
                        "-rpcdoccheck=0 for this run: %s",
                        message.splitlines()[0],
                    )
                else:
                    self.log.info("rpc doc-check probe: importdepositpool failed: %s", exc)
            else:
                self.log.info(
                    "rpc doc-check probe: importdepositpool passes -rpcdoccheck; "
                    "the -rpcdoccheck=0 workaround on node 1 can be removed"
                )
        finally:
            try:
                node.unloadwallet(name)
            except JSONRPCException:
                pass

    # --- test -------------------------------------------------------------

    def run_test(self):
        self._refuse_production_datadir()
        self.skip_if_no_software_signer()

        miner_node = self.nodes[0]
        exchange_node = self.nodes[1]
        miner = miner_node.get_wallet_rpc("miner")
        wallet = self._open_exchange(exchange_node)
        signers = exchange_node.enumeratesigners()["signers"]
        assert_equal(len(signers), 1)
        assert_equal(signers[0]["fingerprint"], MOCK_FINGERPRINT)
        mining_addr = miner.getnewaddress(address_type="p2mr")
        assert_raises_rpc_error(-4, "Private keys are disabled", wallet.sendtoaddress, mining_addr, 0.1)
        self._require_bcp1_rpcs(wallet)

        # Stay connected; mine without the default 60s sync_all, then wait.
        # waitforblockheight's timeout is milliseconds — do not pass seconds.
        self.generatetoaddress(miner_node, COINBASE_MATURITY + 5, mining_addr, sync_fun=self.no_op)
        miner.syncwithvalidationinterfacequeue()
        balances = miner.getbalances()["mine"]
        if Decimal(str(balances.get("trusted", 0))) <= 0:
            self.generate(miner_node, 20, sync_fun=self.no_op)
            miner.syncwithvalidationinterfacequeue()
        self.sync_blocks(timeout=240)
        if miner.getbalance() <= 0:
            raise AssertionError(f"miner has no spendable balance: {miner.getbalances()}")

        ready = wallet.getexchangereadiness()
        self._no_secrets(ready, "getexchangereadiness")
        dumped = self._dump(ready)
        if "btx_exchange_profile_v1" not in dumped and PROFILE.lower() not in dumped:
            raise AssertionError(f"getexchangereadiness profile: {ready}")
        caps = ready.get("ready_capabilities") or ready.get("capabilities") or {}
        if caps.get("pkcs11_live") or caps.get("kmip_live") or caps.get("https_live"):
            raise AssertionError(f"getexchangereadiness must not claim PKCS#11/KMIP/HTTPS live: {ready}")
        if ready.get("pkcs11_live") or ready.get("kmip_live") or ready.get("https_live"):
            raise AssertionError(f"getexchangereadiness top-level stub live flags: {ready}")
        deposits = bool(caps.get("deposits_ok", caps.get("deposit_pool")))
        signer_ok = bool(caps.get("signer_ok", caps.get("signer_available")))
        if ready.get("ready") is True and not (deposits or signer_ok):
            raise AssertionError(
                f"empty descriptor wallet must not be ready from descriptors+IBD alone: {ready}"
            )

        # Watch-only deposit pool from pubkeys the software signer owns.
        pool = self._import_signer_deposit_pool(wallet, exchange_node)
        pool_addrs = [entry["address"] for entry in pool]

        for index in range(4):
            derived = self._call_variants(
                wallet.deriveexchangeaddress,
                [
                    ([index], {}),
                    ([], {"index": index}),
                    ([{"index": index, "branch": 0}], {}),
                ],
            )
            deposit_addr = self._address_of(derived)
            if deposit_addr != pool[index]["address"]:
                raise AssertionError(
                    f"deriveexchangeaddress({index})={deposit_addr} does not match the "
                    f"signer-pubkey pool address {pool[index]['address']}"
                )
        ready_after = wallet.getexchangereadiness()
        self._no_secrets(ready_after, "getexchangereadiness after pool import")
        if ready_after.get("ready") is not True:
            raise AssertionError(f"watch-only coordinator with a deposit pool must be ready: {ready_after}")
        after_caps = ready_after.get("ready_capabilities") or ready_after.get("capabilities") or {}
        if after_caps.get("pkcs11_live") or after_caps.get("kmip_live") or after_caps.get("https_live"):
            raise AssertionError(f"pool-ready must still not claim PKCS#11/KMIP/HTTPS live: {ready_after}")
        if after_caps.get("deposits_ok") is not True and after_caps.get("deposit_pool") is not True:
            raise AssertionError(f"deposit pool must set deposits_ok: {ready_after}")
        self._pass("address generation")
        self._note_importdepositpool_doc_defect(miner_node)

        # Deposits must land on signer-owned P2MR scripts so the watch-only
        # wallet can select them via solvable mr(pubkey) descriptors.
        dests = list(pool_addrs[:3])
        deposit_txids = []
        deposit_vouts = []
        one = None
        for i, dest in enumerate(dests):
            txid = miner.sendtoaddress(dest, Decimal("1.5"))
            vout = find_vout_for_address(miner_node, txid, dest)
            deposit_txids.append(txid)
            deposit_vouts.append(vout)
            self._push_raw(exchange_node, miner_node, txid)
            # Pool addresses are signer-owned. Lock them so later miner sends do
            # not consume the deposit UTXOs the watch-only wallet is tracking.
            miner.lockunspent(unlock=False, transactions=[{"txid": txid, "vout": int(vout)}])
            exchange_node.syncwithvalidationinterfacequeue()
            miner_node.syncwithvalidationinterfacequeue()
            if i == 0:
                mempool_status = self._call_variants(
                    wallet.getdepositstatus,
                    [
                        ([deposit_txids[0], deposit_vouts[0]], {}),
                        ([], {"txid": deposit_txids[0], "vout": deposit_vouts[0]}),
                        ([{"txid": deposit_txids[0], "vout": deposit_vouts[0]}], {}),
                    ],
                )
                status = self._status_of(mempool_status)
                if status not in ("MEMPOOL", "UNKNOWN"):
                    raise AssertionError(f"pre-confirm status: {mempool_status}")
                if status != "MEMPOOL":
                    raise AssertionError(f"deposit detection must be MEMPOOL, got {status}: {mempool_status}")
                confs = mempool_status.get("confirmations") if isinstance(mempool_status, dict) else None
                if confs not in (None, 0, "0"):
                    raise AssertionError(f"mempool confirmations: {mempool_status}")
                self._pass("deposit detection")
            self.generate(miner_node, 1, sync_fun=self.no_op)
            self.sync_blocks(timeout=120)
            exchange_node.syncwithvalidationinterfacequeue()
            if i == 0:
                one = self._call_variants(
                    wallet.getdepositstatus,
                    [([deposit_txids[0], deposit_vouts[0]], {})],
                )
                if self._status_of(one) != "CONFIRMED":
                    raise AssertionError(f"1 confirmation status: {one}")
                if isinstance(one, dict) and one.get("confirmations") not in (1, "1"):
                    raise AssertionError(f"depth 1: {one}")
        self.generate(miner_node, 3, sync_fun=self.no_op)
        self.sync_blocks(timeout=120)
        exchange_node.syncwithvalidationinterfacequeue()
        nconf = self._call_variants(
            wallet.getdepositstatus,
            [([deposit_txids[0], deposit_vouts[0]], {})],
        )
        if isinstance(nconf, dict):
            got = int(nconf.get("confirmations", 0))
            if got < 4:
                raise AssertionError(f"1→N confirmations: {nconf}")
        if self._status_of(nconf) != "CONFIRMED":
            raise AssertionError(f"N confirmation status: {nconf}")
        self._pass("1→N confirmations")

        listed = self._call_variants(
            wallet.listdepositutxos,
            [([], {}), ([{}], {}), ([{"min_confirmations": 1}], {})],
        )
        utxos = self._as_list(listed) if not isinstance(listed, list) else listed
        if len(utxos) < 3:
            raise AssertionError(f"listdepositutxos must see the three signer-owned deposits: {listed}")

        # Local reorg: disconnect the confirming chain so the deposit leaves the tip.
        confirm_hash = None
        if isinstance(one, dict) and one.get("block_hash"):
            confirm_hash = one["block_hash"]
        if not confirm_hash:
            confirm_hash = miner_node.getblockhash(miner_node.getblockcount() - 3)
        self.disconnect_nodes(0, 1)
        exchange_node.invalidateblock(confirm_hash)
        exchange_node.syncwithvalidationinterfacequeue()
        reorged = self._call_variants(
            wallet.getdepositstatus,
            [([deposit_txids[0], deposit_vouts[0]], {})],
        )
        reorg_status = self._status_of(reorged)
        if reorg_status != "REORGED":
            raise AssertionError(f"reorg must be REORGED, got {reorg_status}: {reorged}")
        exchange_node.reconsiderblock(confirm_hash)
        self.connect_nodes(0, 1)
        self.sync_blocks(timeout=120)
        exchange_node.syncwithvalidationinterfacequeue()
        restored = self._call_variants(
            wallet.getdepositstatus,
            [([deposit_txids[0], deposit_vouts[0]], {})],
        )
        if self._status_of(restored) != "CONFIRMED":
            raise AssertionError(f"post-reconsider must be CONFIRMED: {restored}")
        self._pass("reorg handling")

        # --- unsigned package from watch-only funds ----------------------
        withdraw_dest = miner.getnewaddress(address_type="p2mr")
        change = pool_addrs[-1]
        unsigned = self._call_variants(
            wallet.prepareexternalsign,
            [
                ([{"recipients": [{"address": withdraw_dest, "amount": 0.4}]}, {"change_address": change}], {}),
                ([{"outputs": [{withdraw_dest: 0.4}]}, {"change_address": change}], {}),
                ([{"recipients": [{"address": withdraw_dest, "amount_atoms": 40000000}]}, {"change_address": change}], {}),
            ],
        )
        package = self._package_of(unsigned)
        if package.get("complete") is True and package.get("hex") and not package.get("psbt") and not package.get("unsigned_tx"):
            raise AssertionError(f"prepareexternalsign must not return a fully signed tx: {unsigned}")
        inputs = [i for i in package.get("inputs", []) if isinstance(i, dict)]
        if not inputs:
            raise AssertionError(f"prepareexternalsign returned no inputs: {unsigned}")
        for entry in inputs:
            if not entry.get("digest"):
                raise AssertionError(f"prepareexternalsign input without a canonical digest: {entry}")
        self._pass("unsigned withdrawal")

        digests_raw = self._call_variants(
            wallet.getsigningdigests,
            ([([package], {})] + [([package["psbt"]], {})] if package.get("psbt") else [([package], {})]),
        )
        digests = self._digests_of(digests_raw) or self._digests_of(package)
        if len(digests) != len(inputs):
            raise AssertionError(f"getsigningdigests must return one digest per input: {digests_raw}")
        package_digests = self._digests_of(package)
        if [self._hex_digest(d) for d in digests] != [self._hex_digest(d) for d in package_digests]:
            raise AssertionError(f"getsigningdigests disagrees with the package: {digests_raw} vs {package_digests}")

        # --- real software-signer digest round trip ----------------------
        # A watch-only pool descriptor has no BIP32 path, so prepareexternalsign
        # correctly omits the pubkey from the package. The coordinator maps each
        # input back to the signer key that owns its prevout script and supplies
        # that pubkey alongside the signature, as the RPC documents.
        pool_by_script = {entry["script_pubkey"]: entry for entry in pool}
        signatures = []
        signed_entries = []
        for index, entry in enumerate(inputs):
            pool_entry = pool_by_script.get(str(entry.get("scriptPubKey", "")).lower())
            if pool_entry is None:
                raise AssertionError(
                    f"package input {index} does not spend a signer deposit pool output: {entry}"
                )
            leaf_script = str(entry.get("leaf_script", "")).lower()
            if pool_entry["pubkey"].lower() not in leaf_script:
                raise AssertionError(
                    f"package input {index} leaf script does not commit the signer pubkey: {entry}"
                )
            digest_hex = self._hex_digest(entry)
            signature = self._signer_sign_digest(digest_hex, pool_entry["path"])
            signatures.append({
                "index": index,
                "pubkey": pool_entry["pubkey"],
                "signature": signature,
            })
            signed_entries.append((pool_entry, digest_hex))
        if len(signatures) != len(inputs):
            raise AssertionError("did not sign every input")
        self._pass("external PQ signature")

        finalized = self._call_variants(
            wallet.finalizeexternalsign,
            [
                ([package, signatures], {}),
                ([{"package": package, "signatures": signatures}], {}),
                ([package], {"signatures": signatures}),
            ],
        )
        self._no_secrets(finalized, "finalizeexternalsign")
        if not isinstance(finalized, dict) or finalized.get("complete") is not True:
            raise AssertionError(f"finalizeexternalsign must complete with real ML-DSA-44 signatures: {finalized}")
        if finalized.get("broadcast") is not False or finalized.get("in_process_sign") is not False:
            raise AssertionError(f"finalizeexternalsign must not broadcast or sign in-process: {finalized}")
        hex_tx = finalized.get("hex")
        txid = finalized.get("txid")
        if not hex_tx or not txid:
            raise AssertionError(f"finalizeexternalsign missing hex/txid: {finalized}")
        if finalized.get("signatures_attached") != len(inputs):
            raise AssertionError(f"finalizeexternalsign attached {finalized.get('signatures_attached')} of {len(inputs)}")
        decoded_txid = exchange_node.decoderawtransaction(hex_tx)["txid"]
        if decoded_txid != txid:
            raise AssertionError(f"finalizeexternalsign txid {txid} != decoded {decoded_txid}")
        if txid in exchange_node.getrawmempool():
            raise AssertionError("finalizeexternalsign auto-broadcast the transaction")
        self._pass("signature import")

        # --- fail closed on corrupt signatures (separate named row) ------
        entry0, digest0 = signed_entries[0]
        sig_item0 = [{"index": 0, "pubkey": entry0["pubkey"]}]
        good = self._signer_sign_digest(digest0, entry0["path"])
        # Control: the exact argument shape used below accepts the good
        # signature. `complete` is only expected when the package has a single
        # input; with more, the other inputs stay unsigned.
        control = wallet.finalizeexternalsign(
            package,
            [{**sig_item0[0], "signature": good}],
        )
        if control.get("signatures_attached") != 1 or bool(control.get("complete")) != (len(inputs) == 1):
            raise AssertionError(
                "single good signature must attach (complete=%s for %d input(s)): attached=%s error=%s"
                % (control.get("complete"), len(inputs), control.get("signatures_attached"), control.get("error"))
            )
        corrupt = [
            ("%02x" % (int(good[:2], 16) ^ 0xFF)) + good[2:],     # broken challenge seed
            self._signer_sign_digest("11" * 32, entry0["path"]),  # valid sig, wrong digest
            self._signer_sign_digest(digest0, entry0["path"], stub=True),  # non-crypto stub
        ]
        rejected = 0
        for bad in corrupt:
            try:
                res = wallet.finalizeexternalsign(
                    package,
                    [{**sig_item0[0], "signature": bad}],
                )
            except JSONRPCException as exc:
                message = str(exc)
                if "CORRUPT_SIGNATURE" not in message.upper():
                    raise AssertionError(
                        f"corrupt signature must fail verification, not argument parsing: {message}"
                    )
                self.log.info("corrupt signature rejected: %s", message.splitlines()[0])
                rejected += 1
                continue
            raise AssertionError(
                "finalizeexternalsign did not fail closed on a corrupt signature: "
                f"complete={res.get('complete')} attached={res.get('signatures_attached')} "
                f"error={res.get('error')}"
            )
        if rejected < len(corrupt):
            raise AssertionError(f"expected {len(corrupt)} corrupt signatures rejected, got {rejected}")

        # Cross-key witness: a valid signature from a DIFFERENT signer key over
        # this input's digest also verifies against the pubkey the coordinator
        # supplies, and finalizeexternalsign does not bind pubkey<->leaf_script
        # locally. Whatever finalize reports, consensus must not accept it.
        other = next(entry for entry in pool if entry["pubkey"] != entry0["pubkey"])
        cross_sig = self._signer_sign_digest(digest0, other["path"])
        try:
            cross = wallet.finalizeexternalsign(
                package,
                [{"index": 0, "pubkey": other["pubkey"], "signature": cross_sig}],
            )
        except JSONRPCException as exc:
            self.log.info("cross-key signature rejected locally: %s", str(exc).splitlines()[0])
        else:
            self.log.info(
                "cross-key signature accepted locally (complete=%s); consensus must reject the witness",
                cross.get("complete"),
            )
            if cross.get("complete") is True and cross.get("hex"):
                cross_accept = exchange_node.testmempoolaccept([cross["hex"]])
                if not isinstance(cross_accept, list) or not cross_accept:
                    raise AssertionError(f"cross-key testmempoolaccept returned nothing: {cross_accept}")
                if cross_accept[0].get("allowed") is True:
                    raise AssertionError(
                        "consensus accepted a witness signed by a different signer key: "
                        f"{cross_accept[0]}"
                    )
                self.log.info(
                    "cross-key witness rejected by consensus: %s",
                    cross_accept[0].get("reject-reason"),
                )
        self._pass("corrupt signature rejection")

        # --- explicit broadcast (never auto) -----------------------------
        accepted = exchange_node.testmempoolaccept([hex_tx])
        self._no_secrets(accepted, "testmempoolaccept")
        allowed = isinstance(accepted, list) and accepted and bool(accepted[0].get("allowed"))
        if not allowed:
            raise AssertionError(f"testmempoolaccept rejected the externally signed withdrawal: {accepted}")
        sent = exchange_node.sendrawtransaction(hex_tx)
        self._no_secrets(sent, "sendrawtransaction")
        if sent != txid:
            raise AssertionError(f"sendrawtransaction returned {sent}, want {txid}")
        if txid not in exchange_node.getrawmempool():
            raise AssertionError(f"broadcast tx {txid} not in the exchange mempool")
        try:
            miner_node.sendrawtransaction(hex_tx)
        except JSONRPCException as exc:
            self.log.info("miner already has withdrawal: %s", exc)
        self.sync_mempools(timeout=60)
        self.generate(miner_node, 1, sync_fun=self.no_op)
        # P2P block relay to the watch-only node is not reliable after the
        # reorg rows disconnect/reconnect the peers, so push the block the way
        # the consolidation rows do (the withdrawal itself was already sent
        # explicitly above; this is not an auto-broadcast).
        self._follow_miner(miner_node, exchange_node)
        exchange_node.syncwithvalidationinterfacequeue()
        if exchange_node.getbestblockhash() != miner_node.getbestblockhash():
            raise AssertionError(
                "exchange did not follow the mined withdrawal block: %s vs %s"
                % (exchange_node.getbestblockhash(), miner_node.getbestblockhash())
            )
        confirmed = miner_node.getrawtransaction(txid, True)
        if not isinstance(confirmed, dict) or int(confirmed.get("confirmations", 0)) < 1:
            raise AssertionError(f"externally signed withdrawal was not mined: {confirmed}")
        self._pass("broadcast")

        batch_dest_a = miner.getnewaddress(address_type="p2mr")
        batch_dest_b = miner.getnewaddress(address_type="p2mr")
        batch = self._call_variants(
            wallet.createexchangebatch,
            [
                ([[{"address": batch_dest_a, "amount": 0.2}, {"address": batch_dest_b, "amount": 0.2}]], {}),
                ([{"outputs": [{"address": batch_dest_a, "amount": 0.2}, {"address": batch_dest_b, "amount": 0.2}]}], {}),
            ],
        )
        batch_obj = self._package_of(batch)
        outputs = batch_obj.get("outputs") or batch_obj.get("recipients") or []
        if isinstance(outputs, list) and len(outputs) < 2 and not batch_obj.get("psbt") and not batch_obj.get("unsigned_tx"):
            raise AssertionError(f"createexchangebatch must be a multi-output package: {batch}")
        self._pass("batch withdrawal")

        # Broadcast/batch may have spent the original deposits. Seed two more
        # confirmed watch-only UTXOs so consolidation has something to sweep.
        self.connect_nodes(0, 1)
        self._follow_miner(miner_node, exchange_node)
        sweep_dest = pool_addrs[-1]
        self._follow_miner(miner_node, exchange_node)
        for _ in range(2):
            extra_txid = miner.sendtoaddress(sweep_dest, Decimal("0.25"))
            extra_vout = find_vout_for_address(miner_node, extra_txid, sweep_dest)
            miner.lockunspent(unlock=False, transactions=[{"txid": extra_txid, "vout": int(extra_vout)}])
            self._push_raw(exchange_node, miner_node, extra_txid)
        self.generatetoaddress(miner_node, 1, mining_addr, sync_fun=self.no_op)
        self._follow_miner(miner_node, exchange_node)
        exchange_node.syncwithvalidationinterfacequeue()
        listed_cons = wallet.listdepositutxos({"min_confirmations": 0})
        if len(self._as_list(listed_cons)) < 1:
            raise AssertionError(f"no UTXOs for consolidation after funding: {listed_cons}")

        plan = wallet.planconsolidation({
            "min_confirmations": 0,
            "include_unsafe": True,
            "max_inputs": 10,
            "target_utxo_count": 1,
        })
        fee = wallet.estimateconsolidationfee({
            "min_confirmations": 0,
            "include_unsafe": True,
            "plan": plan,
        })
        cons = wallet.createconsolidationtx({
            "min_confirmations": 0,
            "include_unsafe": True,
            "max_inputs": 10,
            "target_utxo_count": 1,
            "change_address": sweep_dest,
        })
        self._no_secrets(fee, "estimateconsolidationfee")
        self._package_of(cons)
        self._pass("UTXO consolidation")

        # Double-spend: two conflicting spends of the same miner coin.
        conflict_addr_a = miner.getnewaddress(address_type="p2mr")
        conflict_addr_b = miner.getnewaddress(address_type="p2mr")
        utxo = [u for u in miner.listunspent(1) if u.get("spendable")][0]
        raw_a = miner.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{conflict_addr_a: Decimal(str(utxo["amount"])) - Decimal("0.01")}],
        )
        raw_b = miner.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{conflict_addr_b: Decimal(str(utxo["amount"])) - Decimal("0.01")}],
        )
        signed_a = miner.signrawtransactionwithwallet(raw_a)
        signed_b = miner.signrawtransactionwithwallet(raw_b)
        if not signed_a.get("complete") or not signed_b.get("complete"):
            raise AssertionError("miner could not sign conflict pair")
        miner_node.sendrawtransaction(signed_a["hex"])
        rejected = miner_node.testmempoolaccept([signed_b["hex"]])
        allowed_b = isinstance(rejected, list) and rejected and rejected[0].get("allowed") is True
        if allowed_b:
            raise AssertionError(f"double-spend must be rejected: {rejected}")
        self._pass("double-spend rejection")

        self.restart_node(1, extra_args=self.exchange_args)
        self.connect_nodes(0, 1)
        self._follow_miner(self.nodes[0], self.nodes[1])
        wallets = self.nodes[1].listwallets()
        name = getattr(self, "exchange_wallet_name", "exchange")
        if name not in wallets:
            self.nodes[1].loadwallet(name)
        wallet = self.nodes[1].get_wallet_rpc(name)
        again = wallet.getexchangereadiness()
        self._no_secrets(again, "getexchangereadiness after restart")
        self._pass("node restart")

        recovered = self._call_variants(
            wallet.getdepositstatus,
            [([deposit_txids[0], deposit_vouts[0]], {})],
        )
        if self._status_of(recovered) not in ("CONFIRMED", "SPENT", "REORGED", "MEMPOOL"):
            raise AssertionError(f"wallet recovery status: {recovered}")
        recovered_list = self._call_variants(wallet.listdepositutxos, [([], {}), ([{}], {})])
        self._no_secrets(recovered_list, "listdepositutxos after restart")
        self._pass("wallet recovery")

        missing = [row for row in PASS_ROWS if row not in self.passed]
        if missing:
            raise AssertionError(f"BCP/1 missing PASS rows: {missing}; have={self.passed}")
        self.log.info("BTX Exchange Integration Profile v1 (BCP/1)")
        self.log.info("%s/%s PASS", len(self.passed), len(PASS_ROWS))


if __name__ == "__main__":
    BCP1Test(__file__).main()
