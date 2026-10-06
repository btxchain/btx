#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Check that every RPC command renders its help, in the full listing and alone.

The full `help` listing is made of the first line of each command's help
text. If generating that text throws, the listing shows the first line of the
error ("Internal bug detected: ...") in place of the command's summary, so the
command silently drops out of the listing, and `help <command>` returns the
error instead of the help text.
"""

from test_framework.test_framework import BitcoinTestFramework

INTERNAL_BUG = "Internal bug detected"


class RPCHelpSummaryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        # Release builds default to -rpcdoccheck=0, so this is the help that
        # operators see.
        self.extra_args = [["-rpcdoccheck=0"]]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("The full listing has a summary line for every command")
        listing = node.help()
        bad = [line for line in listing.splitlines() if INTERNAL_BUG in line]
        if bad:
            raise AssertionError(f"{len(bad)} line(s) containing '{INTERNAL_BUG}' in the full help listing")

        self.log.info("Every listed command renders its own help")
        calls = [line.split(" ", 1)[0] for line in listing.splitlines() if line and not line.startswith("==")]
        for call in calls:
            text = node.help(call)
            assert not text.startswith("help: unknown command"), call
            assert INTERNAL_BUG not in text, f"help {call}: {text.splitlines()[0]}"
        self.log.info(f"{len(calls)} commands checked")

        self.log.info("An object nested in an object argument appears in the one-line summary")
        assert '\nverifymatmulserviceproofs [{"challenge":{},"nonce64_hex":"hex","digest_hex":"hex","matrix_c_data":"hex"},...] ( include_local_registry_status )\n' in listing

        self.log.info("A result field of unspecified shape (RPCResult::Type::ANY) is documented")
        text = node.help("getmatmulservicechallenge")
        assert text.startswith("getmatmulservicechallenge ")
        assert '"binding" : ...,' in text
        assert "(json value) Application binding plus anchor metadata" in text


if __name__ == '__main__':
    RPCHelpSummaryTest(__file__).main()
