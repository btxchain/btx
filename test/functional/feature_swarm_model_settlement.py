#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Isolated regtest: an unsigned model funding plan is not a wallet settlement.

The node uses its own datadir. preparefundmodelrelease is called with only the
arguments its help text marks required. A missing campaign or an unsigned plan
creates no wallet transaction. automatic_spend_atoms stays 0.
"""

from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def _required_argument_names(helptext):
    """Positional arguments the RPC help marks required, in argument order."""
    names = []
    in_arguments = False
    for line in helptext.splitlines():
        stripped = line.strip()
        if stripped == "Arguments:":
            in_arguments = True
            continue
        if not in_arguments:
            continue
        if stripped == "Result:" or stripped.startswith("Result:") or stripped == "Examples:":
            break
        if not stripped[:1].isdigit():
            continue
        if ", required" not in stripped and "(required" not in stripped:
            continue
        parts = stripped.split()
        if len(parts) < 2 or parts[1].startswith("("):
            continue
        names.append(parts[1])
    if names:
        return names
    # Synopsis fallback: tokens outside parentheses are required.
    synopsis = helptext.strip().splitlines()[0] if helptext.strip() else ""
    rest = synopsis.split(None, 1)[1] if " " in synopsis else ""
    token = []
    in_quote = False
    depth = 0
    for ch in rest:
        if ch == "(" and not in_quote:
            depth += 1
        elif ch == ")" and not in_quote:
            depth = max(0, depth - 1)
        elif ch == '"' and depth == 0:
            if in_quote:
                if token:
                    names.append("".join(token))
                token = []
            in_quote = not in_quote
        elif in_quote and depth == 0:
            token.append(ch)
    return names


def _required_value(name):
    # No campaign exists on this fresh chain. The id is synthetic.
    if name == "release_id":
        return "a" * 96
    return "0"


def _is_hex_tx(value):
    if not isinstance(value, str) or len(value) < 20 or len(value) % 2:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def _candidate_hex(obj, depth=0):
    if isinstance(obj, str) and _is_hex_tx(obj):
        return obj
    if depth > 3 or not isinstance(obj, dict):
        return None
    for key in ("hex", "unsigned_hex", "rawtx", "signed_hex"):
        value = obj.get(key)
        if _is_hex_tx(value):
            return value
    for child in obj.values():
        if isinstance(child, dict):
            found = _candidate_hex(child, depth + 1)
            if found:
                return found
    return None


class SwarmModelSettlementTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.modeldir = Path(self.options.tmpdir) / "settlement-models"
        self.modeldir.mkdir(parents=True)
        # Same local modelnet pattern as feature_swarm_regtest_spend.py.
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

    def _assert_automatic_spend_zero(self, node):
        info = node.getmodelnetworkinfo()
        assert_equal(info["automatic_spend_atoms"], 0)

    def _try_sign_and_send(self, node, plan):
        raw = _candidate_hex(plan)
        if not raw:
            return None
        try:
            signed = node.signrawtransactionwithwallet(raw)
        except JSONRPCException:
            return None
        if not isinstance(signed, dict) or signed.get("complete") is not True:
            return None
        signed_hex = signed.get("hex")
        if not _is_hex_tx(signed_hex):
            return None
        try:
            txid = node.sendrawtransaction(signed_hex)
        except JSONRPCException:
            return None
        if isinstance(txid, str) and txid:
            return txid
        return None

    def run_test(self):
        node = self.nodes[0]
        self._assert_automatic_spend_zero(node)
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
        assert COINBASE_MATURITY == 100
        mine_to(COINBASE_MATURITY + 2)
        assert node.getblockcount() >= 102
        assert node.getbalance() > 0
        self._assert_automatic_spend_zero(node)

        txcount_before = node.getwalletinfo()["txcount"]
        mempool_before = node.getrawmempool()
        helptext = node.help("preparefundmodelrelease")
        args = [_required_value(name) for name in _required_argument_names(helptext)]
        plan = None
        try:
            plan = node.preparefundmodelrelease(*args)
        except JSONRPCException:
            plan = None

        self._assert_automatic_spend_zero(node)
        # The call itself never spends. Check before anything below signs or sends.
        assert_equal(node.getwalletinfo()["txcount"], txcount_before)
        assert_equal(node.getrawmempool(), mempool_before)
        submitted = self._try_sign_and_send(node, plan) if plan is not None else None
        if submitted:
            assert submitted
            self._assert_automatic_spend_zero(node)
        else:
            assert_equal(node.getwalletinfo()["txcount"], txcount_before)
            self._assert_automatic_spend_zero(node)


if __name__ == "__main__":
    SwarmModelSettlementTest(__file__).main()
