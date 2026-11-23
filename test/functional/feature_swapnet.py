#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers. Distributed under the MIT license.
"""Native integration: explicit discovery, RPC coverage, persistence, disable switch.
No simulated settlement is counted as real-chain settlement by this test.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal,assert_raises_rpc_error

class SwapNetTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes=2;self.setup_clean_chain=True
        self.extra_args=[['-modelbind=off'],['-modelbind=off']]
    def run_test(self):
        a,b=self.nodes
        self.wait_until(lambda:a.getswapbootstrapinfo()['admitted_peers']>=1 and b.getswapbootstrapinfo()['admitted_peers']>=1)
        info=a.getswapnetworkinfo();assert_equal(info['protocol'],2);assert_equal(info['in_process'],True)
        assert_equal(info['automatic_spend_atoms'],'0');assert_equal(info['network'],a.getblockhash(0))
        caps=a.getswapcapabilities();assert_equal(len(caps['methods']),56)
        assert_equal(any(m['name']=='inspectswapinvite' and m['scope']=='read' for m in caps['methods']), True)
        assert_equal(any(m['name']=='getswaptradepreview' and m['scope']=='owner' for m in caps['methods']), True)
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
        # A SwapNet start that fails stops the node with an init error that names the reason and -swapnet=0.
        self.stop_node(0);args=self.extra_args[0]
        self.nodes[0].assert_start_raises_init_error(args+['-swapnetmode=bogus'],r'Error: SwapNet could not start \(unknown -swapnetmode\)\. No funds were authorized by startup\..*-swapnet=0',match=ErrorMatch.PARTIAL_REGEX)
        key=self.nodes[0].chain_path/'swapnet'/'vault.key';saved=key.read_bytes()
        key.write_bytes(b'short')
        self.nodes[0].assert_start_raises_init_error(args,r'Error: SwapNet could not start \(.*VAULT_FORMAT.*\)\..*-swapnet=0',match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0,args+['-swapnet=0']);assert_raises_rpc_error(-1,'disabled',self.nodes[0].getswapnetworkinfo)
        self.stop_node(0);key.write_bytes(saved)
        self.start_node(0,args);assert_equal(self.nodes[0].getswaphealth()['audit_head'],before)

if __name__=='__main__':SwapNetTest(__file__).main()
