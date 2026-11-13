#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers. Distributed under the MIT license.
"""Native integration: explicit discovery, RPC coverage, persistence, disable switch.
No simulated settlement is counted as real-chain settlement by this test.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal,assert_raises_rpc_error

class SwapNetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes=2;self.setup_clean_chain=True
        self.extra_args=[['-modelbind=off','-swapnet=1'],['-modelbind=off','-swapnet=1']]
    def run_test(self):
        a,b=self.nodes
        self.wait_until(lambda:a.getswapbootstrapinfo()['admitted_peers']>=1 and b.getswapbootstrapinfo()['admitted_peers']>=1)
        info=a.getswapnetworkinfo();assert_equal(info['protocol'],2);assert_equal(info['in_process'],True)
        assert_equal(info['automatic_spend_atoms'],'0');assert_equal(info['network'],a.getblockhash(0))
        caps=a.getswapcapabilities();assert_equal(len(caps['methods']),33)
        assert_equal(a.getswapbootstrapinfo()['separate_seeds'],False)
        assert_equal(a.getswapbootstrapinfo()['fabricated_liquidity'],False)
        assert_equal(a.listswaps()['swaps'],[])
        # Public JSON cannot impersonate native owner context or force spending.
        assert_raises_rpc_error(-1,'PARAMS',a.publishswapprovider,{'owner':True})
        before=a.getswaphealth()['audit_head']
        self.restart_node(0,self.extra_args[0]);assert_equal(self.nodes[0].getswaphealth()['audit_head'],before)
        self.connect_nodes(0,1)
        self.wait_until(lambda:self.nodes[0].getswapbootstrapinfo()['admitted_peers']>=1)
        self.restart_node(1,['-modelbind=off','-swapnet=0'])
        assert_raises_rpc_error(-1,'disabled',self.nodes[1].getswapnetworkinfo)

if __name__=='__main__':SwapNetTest(__file__).main()
