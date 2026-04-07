#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Disconnect peers that trigger message deserialization failures."""

from test_framework.messages import msg_generic
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework


class SenderOfAddrV2(P2PInterface):
    def wait_for_sendaddrv2(self):
        self.wait_until(lambda: 'sendaddrv2' in self.last_message)


class P2PDeserializationFailuresTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def assert_malformed_addrv2_disconnect(self, payload, expected_detail):
        node = self.nodes[0]
        conn = node.add_p2p_connection(SenderOfAddrV2())
        conn.wait_for_sendaddrv2()

        with node.assert_debug_log([
            'Misbehaving',
            'deserialization error while parsing addrv2',
            expected_detail,
        ]):
            conn.send_message(msg_generic(b'addrv2', payload))
            conn.wait_for_disconnect(timeout=5)

    def run_test(self):
        self.log.info('Reject empty addrv2 payload that cannot be decoded')
        self.assert_malformed_addrv2_disconnect(b'', 'end of data')

        self.log.info('Reject addrv2 payload with oversized address element')
        oversized_addr_payload = bytes.fromhex(
            '01' +       # number of entries
            '61bc6649' + # time, Fri Jan  9 02:54:25 UTC 2009
            '00' +       # service flags, COMPACTSIZE(NODE_NONE)
            '01' +       # network type (IPv4)
            'fd0102' +   # address length (COMPACTSIZE(513))
            'ab' * 513 + # address
            '208d'       # port
        )
        self.assert_malformed_addrv2_disconnect(oversized_addr_payload, 'Address too long: 513 > 512')


if __name__ == '__main__':
    P2PDeserializationFailuresTest(__file__).main()
