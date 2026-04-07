#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the generation of UTXO snapshots using `dumptxoutset`.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    sha256sum_file,
)
import hashlib
import os


class DumptxoutsetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def check_expected_network(self, node, active):
        rev_file = node.blocks_path / "rev00000.dat"
        bogus_file = node.blocks_path / "bogus.dat"
        rev_file.rename(bogus_file)
        assert_raises_rpc_error(
            -1, 'Could not roll back to requested height.', node.dumptxoutset, 'utxos.dat', rollback=99)
        assert_equal(node.getnetworkinfo()['networkactive'], active)

        # Cleanup
        bogus_file.rename(rev_file)

    @staticmethod
    def check_output_file(path, is_human_readable, expected_digest=None):
        with open(str(path), 'rb') as f:
            content = f.read()

            if is_human_readable:
                # Normalise platform EOL to \n, while making sure any stray \n becomes a literal backslash+n to avoid a false positive
                # This ensures the platform EOL and only the platform EOL produces the expected hash
                linesep = os.linesep.encode('utf8')
                content = b'\n'.join(line.replace(b'\n', b'\\n') for line in content.split(linesep))

            digest = hashlib.sha256(content).hexdigest()
            if expected_digest is not None:
                # UTXO snapshot hash should be deterministic based on mocked time.
                assert_equal(digest, expected_digest)
            return digest

    def test_dump_file(self, testname, params, expected_digest=None):
        node = self.nodes[0]

        self.log.info(testname)
        filename = testname + '_txoutset.dat'
        is_human_readable = not params.get('format') is None

        out = node.dumptxoutset(path=filename, type="latest", **params)
        expected_path = node.chain_path / filename

        assert expected_path.is_file()

        assert_equal(out['coins_written'], 100)
        assert_equal(out['base_height'], 100)
        assert_equal(out['path'], str(expected_path))
        assert_equal(out['base_hash'], self.expected_base_hash)

        snapshot_digest = self.check_output_file(expected_path, is_human_readable, expected_digest)

        if {'format'} == set(params) - {'show_header', 'separator'}:
            # Test backward compatibility
            def test_dump_file_compat(*a, **ka):
                os.replace(expected_path, node.chain_path / (filename + ".old"))
                out2 = node.dumptxoutset(filename, *a, **ka)
                assert_equal(out, out2)
                self.check_output_file(expected_path, is_human_readable, snapshot_digest)
            test_dump_file_compat(params.get('format'), params.get('show_header'), params.get('separator'))
            test_dump_file_compat(params.get('format'), params.get('show_header'), separator=params.get('separator'))
            test_dump_file_compat(params.get('format'), show_header=params.get('show_header'), separator=params.get('separator'))

        if not hasattr(self, "expected_txoutset_hash"):
            self.expected_txoutset_hash = out['txoutset_hash']
        assert_equal(out['txoutset_hash'], self.expected_txoutset_hash)
        if not hasattr(self, "expected_nchaintx"):
            self.expected_nchaintx = out['nchaintx']
        assert_equal(out['nchaintx'], self.expected_nchaintx)

        self.log.info("Test that a path to an existing or invalid file will fail")
        assert_raises_rpc_error(
            -8, '{} already exists'.format(filename),  node.dumptxoutset, filename, "latest")
        invalid_path = node.datadir_path / "invalid" / "path"
        assert_raises_rpc_error(
            -8, "Couldn't open file {}.incomplete for writing".format(invalid_path), node.dumptxoutset, invalid_path, "latest")

        self.log.info("Test that dumptxoutset with unknown dump type fails")
        assert_raises_rpc_error(
            -8, 'Invalid snapshot type "bogus" specified. Please specify "rollback" or "latest"', node.dumptxoutset, 'utxos.dat', "bogus")

        self.log.info("Test that dumptxoutset failure does not leave the network activity suspended when it was on previously")
        self.check_expected_network(node, True)

        self.log.info("Test that dumptxoutset failure leaves the network activity suspended when it was off")
        node.setnetworkactive(False)
        self.check_expected_network(node, False)
        node.setnetworkactive(True)

        if params.get('format') == ():
            with open(expected_path, 'r', encoding='utf-8') as f:
                content = f.readlines()
                sep = params.get('separator', ',')
                if params.get('show_header', True):
                    assert_equal(content.pop(0).rstrip(),
                        "#(blockhash {h} ) txid{s}vout{s}value{s}coinbase{s}height{s}scriptPubKey".format(h=out['base_hash'], s=sep))
                first = content[0].rstrip().split(sep)
                assert_equal(len(first), 6)
                assert_equal(first[1], '0')
                assert_equal(first[2], '5000000000')
                assert first[3] in {'0', '1'}
                assert int(first[4]) >= 1
                assert len(first[5]) <= 68

    def run_test(self):
        """Test a trivial usage of the dumptxoutset RPC command."""
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getblockhash(0))['time'] + 1
        node.setmocktime(mocktime)
        self.generate(node, COINBASE_MATURITY)
        self.expected_base_hash = node.getbestblockhash()

        self.test_dump_file('no_option',           {})
        self.test_dump_file('all_data',            {'format': ()})
        self.test_dump_file('partial_data_1',      {'format': ('txid',)})
        self.test_dump_file('partial_data_order',  {'format': ('height', 'vout')})
        self.test_dump_file('partial_data_double', {'format': ('scriptPubKey', 'scriptPubKey')})
        self.test_dump_file('no_header',           {'format': (), 'show_header': False})
        self.test_dump_file('separator',           {'format': (), 'separator': ':'})
        self.test_dump_file('all_options',         {'format': (), 'show_header': False, 'separator': ':'})

        # Other failing tests
        assert_raises_rpc_error(
            -8, 'unable to find item \'sample\'',  node.dumptxoutset, path='xxx', type='latest', format=['sample'])

if __name__ == '__main__':
    DumptxoutsetTest(__file__).main()
