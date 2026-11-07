#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""A wallet sendtoaddress on an isolated regtest node must move coins.

Modelnet is local only: no helper process and no model-funding transaction.
automatic_spend_atoms stays 0. A helper_error from the absent helper is acceptable.
"""

import json
from decimal import Decimal
from pathlib import Path

from test_framework.blocktools import COINBASE_MATURITY, REGTEST_INITIAL_SUBSIDY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def _automatic_spend_is_zero(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        return value == "0"
    if isinstance(value, (int, Decimal)):
        return value == 0
    return False


def _assert_automatic_spend_fields(obj, where):
    if isinstance(obj, dict):
        if "automatic_spend_atoms" in obj:
            value = obj["automatic_spend_atoms"]
            assert _automatic_spend_is_zero(value), (
                f"{where} automatic_spend_atoms={value!r}"
            )
        for key, child in obj.items():
            _assert_automatic_spend_fields(child, f"{where}.{key}")
    elif isinstance(obj, list):
        for index, child in enumerate(obj):
            _assert_automatic_spend_fields(child, f"{where}[{index}]")


class SwarmRegtestSpendTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.modeldir = Path(self.options.tmpdir) / "spend-models"
        self.modeldir.mkdir(parents=True)
        # Same local modelnet pattern as feature_swarm_catalog.py, with the wallet left enabled.
        self.extra_args = [[
            "-modelnet=1",
            "-modelnetrequired=0",
            "-modelbind=off",
            "-modelstorage=0",
            f"-modeldir={self.modeldir}",
            f"-modelhelper={self.modeldir / 'absent-helper'}",
            # Keep regtest block production off the matmul path so a coinbase can mature.
            "-regtestmatmulbindingheight=2147483647",
            "-regtestmatmulproductdigestheight=2147483647",
            "-regtestmatmulv4height=2147483647",
            "-regtestmatmulrequireproductpayload=0",
        ]]
        super().setup_nodes()

    def _assert_swarm_json_spend(self):
        roots = [self.modeldir]
        datadir = Path(self.nodes[0].datadir_path)
        if datadir.exists():
            roots.append(datadir)
        seen = set()
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*.json"):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                posix = path.as_posix()
                under_modeldir = path == self.modeldir or self.modeldir in path.parents
                if not under_modeldir and "swarm" not in posix and "modelnet" not in posix:
                    continue
                text = path.read_text(encoding="utf8")
                if "automatic_spend_atoms" not in text:
                    continue
                _assert_automatic_spend_fields(json.loads(text), str(path))

    def run_test(self):
        node = self.nodes[0]
        # self.generate pays the deterministic key, which this wallet does not own.
        wallet_addr = node.getnewaddress()

        def mine_to(height):
            stalls = 0
            while node.getblockcount() < height:
                before = node.getblockcount()
                step = min(20, height - before)
                self.generatetoaddress(node, step, wallet_addr)
                if node.getblockcount() == before:
                    stalls += 1
                    if stalls > 3:
                        raise AssertionError(f"mining stalled at height {before}")
                else:
                    stalls = 0
            self.wait_until(lambda: node.getwalletinfo()["lastprocessedblock"]["height"] == node.getblockcount())

        # Coinbase at height h is spendable once depth reaches COINBASE_MATURITY + 1.
        # Tip 102 matures the coinbases from heights 1 and 2.
        mine_to(COINBASE_MATURITY + 2)
        balance_before = node.getbalance()
        assert_equal(balance_before, 2 * Decimal(REGTEST_INITIAL_SUBSIDY))
        dest = node.getnewaddress()
        txid = node.sendtoaddress(dest, 1)
        mine_to(node.getblockcount() + 1)

        received = node.getreceivedbyaddress(dest)
        assert_equal(received, Decimal("1"))
        balance_after = node.getbalance()
        assert balance_after != balance_before, "wallet spend did not move the sender balance"
        fee = node.gettransaction(txid)["fee"]
        assert isinstance(fee, Decimal) and fee < 0, "wallet spend did not move coins"
        # The extra block matures one more coinbase. The same-wallet send pays only its fee.
        assert_equal(balance_after, balance_before + Decimal(REGTEST_INITIAL_SUBSIDY) + fee)

        info = node.getmodelnetworkinfo()
        assert_equal(info["automatic_spend_atoms"], 0)
        _assert_automatic_spend_fields(info, "getmodelnetworkinfo")
        self._assert_swarm_json_spend()


if __name__ == "__main__":
    SwarmRegtestSpendTest(__file__).main()
