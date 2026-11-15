#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Check btx-cli stdin passphrases in all-named wallet bundle calls.

btx-cli inserts a passphrase read with -stdinwalletpassphrase or
-stdinbundlepassphrase into the argument list. With -named and only named
arguments, a bare inserted value would become the first positional argument
and collide with the named destination, so the CLI must pass it by name.
Keyword arguments make the test framework call btx-cli with -named.
"""

from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_process_error,
    assert_raises_rpc_error,
)

PASSPHRASE = "pass"
ARCHIVE_PASSPHRASE = "archive-pass"
TWICE = "wallet_passphrase was supplied both explicitly and through a stdin passphrase option"


class WalletBackupBundleCliNamedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.rpc_timeout = 120
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()
        self.skip_if_no_cli()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="source", descriptors=True, passphrase=PASSPHRASE)
        source = node.get_wallet_rpc("source")
        source.walletlock()

        def cli(*options, stdin):
            return node.cli("-rpcwallet=source", *options, input=stdin)

        self.log.info("backupwalletbundle with a named destination and -stdinwalletpassphrase")
        bundle = cli("-stdinwalletpassphrase", stdin=PASSPHRASE + "\n").backupwalletbundle(
            destination=node.datadir_path / "named.bundle",
        )
        assert_equal(bundle["unlocked_by_rpc"], True)
        assert (Path(bundle["bundle_dir"]) / "manifest.json").is_file()
        assert_raises_rpc_error(-13, "walletpassphrase first", source.listdescriptors, True)

        self.log.info("A second, explicit wallet_passphrase is refused")
        assert_raises_process_error(
            1,
            TWICE,
            cli("-stdinwalletpassphrase", stdin=PASSPHRASE + "\n").backupwalletbundle,
            destination=node.datadir_path / "twice.bundle",
            wallet_passphrase=PASSPHRASE,
        )

        self.log.info("backupwalletbundlearchive with named arguments and both stdin passphrases")
        archive = cli("-stdinwalletpassphrase", "-stdinbundlepassphrase", stdin=f"{PASSPHRASE}\n{ARCHIVE_PASSPHRASE}\n").backupwalletbundlearchive(
            destination_archive=node.datadir_path / "named.bundle.btx",
        )
        assert_equal(archive["unlocked_by_rpc"], True)
        assert Path(archive["archive_file"]).is_file()

        self.log.info("restorewalletbundlearchive with named arguments and -stdinbundlepassphrase")
        restore = node.cli("-stdinbundlepassphrase", input=ARCHIVE_PASSPHRASE + "\n").restorewalletbundlearchive(
            wallet_name="restored",
            archive_file=archive["archive_file"],
        )
        assert_equal(restore["name"], "restored")
        restored = node.get_wallet_rpc("restored")
        assert_raises_rpc_error(-13, "walletpassphrase first", restored.listdescriptors, True)


if __name__ == "__main__":
    WalletBackupBundleCliNamedTest(__file__).main()
