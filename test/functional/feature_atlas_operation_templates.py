#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Check the Atlas operation templates against this node's RPC signatures.

gui/atlas/web/views/operations.js sends a template as positional parameters,
one per template argument, in order: a field left empty is skipped at the end
and sent as null in the middle, and a field with a default sends the default.
Call every template that way and keep the node's own answer. A template is
broken when the node does not know the method, takes fewer arguments, or
rejects the type of an argument; any other answer (an unknown id, no model
helper, an invalid address) means the shape was accepted.
"""

import json
import re
from pathlib import Path

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "gui" / "atlas" / "schemas" / "operations.json"
CATALOG = ROOT / "gui" / "atlas" / "web" / "core" / "catalog.js"

# Calls that would stop the node, block, or lock or unload the wallet this
# test uses. Only their argument count is compared with the help.
NOT_CALLED = {
    "stop", "encryptwallet", "walletpassphrase", "walletpassphrasechange", "walletlock",
    "unloadwallet", "waitfornewblock", "waitforblock", "waitforblockheight", "waitformodelevent",
}


def help_arg_count(text):
    return len(re.findall(r"^\d+\. \w+\s+\(", text, re.M))


class AtlasOperationTemplatesTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def sample(self, op, index, arg):
        if arg["kind"] == "boolean":
            # A checkbox always sends its state.
            return arg.get("default") is True
        if "default" in arg and arg["default"] is not None and arg["default"] != "":
            return arg["default"]
        if not arg.get("required"):
            return None
        kind = arg["kind"]
        if kind in ("path", "savepath"):
            return str(Path(self.options.tmpdir) / f"atlas-{op['method']}-{index}")
        if kind == "enum":
            return arg["options"][0]
        if kind == "boolean":
            return True
        if kind == "integer":
            return 1
        if kind == "amount":
            return "0.001"
        if kind == "json":
            return {}
        return "atlas"

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="atlas", descriptors=True)
        operations = json.loads(TEMPLATES.read_text(encoding="utf8"))["operations"]
        generated = CATALOG.read_text(encoding="utf8")
        listed = {line.split()[0] for line in node.help().splitlines() if line and not line.startswith("==")}
        problems = []
        for op in operations:
            method = op["method"]
            if f'"method": "{method}"' not in generated:
                problems.append(f"{method}: in operations.json but not in web/core/catalog.js")
            if method not in listed:
                problems.append(f"{method}: the node has no such RPC")
                continue
            help_text = node.help(method)
            params = [self.sample(op, i, a) for i, a in enumerate(op.get("args", []))]
            while params and params[-1] is None:
                params.pop()
            if len(params) > help_arg_count(help_text):
                problems.append(f"{method}: the template sends {len(params)} arguments, the RPC takes {help_arg_count(help_text)}")
                continue
            if method in NOT_CALLED:
                continue
            rpc = node.get_wallet_rpc("atlas") if op.get("wallet") else node
            try:
                rpc.__getattr__(method)(*params)
            except JSONRPCException as e:
                message = str(e.error.get("message", ""))
                if e.error.get("code") == -3 and "Wrong type passed" in message:
                    problems.append(f"{method}: the node rejects the argument types: {' '.join(message.split())}")
                elif e.error.get("code") == -1 and message.startswith(help_text.splitlines()[0]):
                    problems.append(f"{method}: the node rejects {len(params)} arguments (signature: {help_text.splitlines()[0]})")
        for p in problems:
            self.log.error(p)
        assert not problems, f"{len(problems)} Atlas templates do not match the node"


if __name__ == "__main__":
    AtlasOperationTemplatesTest(__file__).main()
