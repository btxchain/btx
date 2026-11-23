#!/usr/bin/env python3
"""Native default startup, authorization and inert invitation checks.
These are NOT funded cross-chain settlement tests.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal,assert_raises_rpc_error

class SwapNetMarketTest(BitcoinTestFramework):
    def add_options(self,parser):self.add_wallet_options(parser,legacy=False)
    def set_test_params(self):
        self.num_nodes=2;self.setup_clean_chain=True;self.wallet_names=[]
        self.extra_args=[['-modelbind=off'],['-modelbind=off']]
    def skip_test_if_missing_module(self):self.skip_if_no_wallet()
    def run_test(self):
        a,b=self.nodes
        a.createwallet(wallet_name='maker',load_on_startup=True,descriptors=True)
        b.createwallet(wallet_name='taker',load_on_startup=True,descriptors=True)
        self.wait_until(lambda:a.getswapbootstrapinfo()['admitted_peers']>0 and b.getswapbootstrapinfo()['admitted_peers']>0)
        assert_equal(a.getswapmode()['mode'],'taker');assert_equal(a.getswapmode()['making_enabled'],False)
        assert_equal(a.getswapnetworkinfo()['automatic_spend_atoms'],'0')
        assert_equal(a.listswappublicoffers()['offers'],[])
        before=len(b.getpeerinfo())
        invite=a.createswapinvite({'endpoints':['93.184.216.34:29447'],'ttl':60})
        preview=b.inspectswapinvite({'uri':invite['uri']})
        assert_equal(preview['signature_verified'],True);assert_equal(preview['connection_started'],False)
        assert_equal(preview['spending_authority'],False);assert_equal(len(b.getpeerinfo()),before)
        assert_raises_rpc_error(-1,'INVITE_ENDPOINT',a.createswapinvite,{'endpoints':['127.0.0.1:8332'],'ttl':60})
        a.setswapmode({'mode':'maker'});assert_equal(a.getswapmode()['making_enabled'],True)
        a.setswapmode({'mode':'observe'});assert_equal(a.getswapmode()['existing_obligations_recovery_enabled'],True)
        # btx-cli converts the request object: by position, by name, and from -stdin as contrib/swapnet/tools/btx_market.py sends it.
        a.cli.setswapmode({'mode':'maker'});assert_equal(a.getswapmode()['mode'],'maker')
        a.cli.setswapmode(request={'mode':'taker'});assert_equal(a.getswapmode()['mode'],'taker')
        a.cli('-stdin',input='{"mode":"observe"}\n').setswapmode();assert_equal(a.getswapmode()['mode'],'observe')
        self.restart_node(0,['-modelbind=off','-swapnet=1','-swapnetmode=recovery'])
        assert_equal(self.nodes[0].getswapmode()['mode'],'recovery')
        assert_raises_rpc_error(-1,'MODE_LOCKED',self.nodes[0].setswapmode,{'mode':'maker'})
        assert_equal(self.nodes[0].listswaps()['swaps'],[])

if __name__=='__main__':SwapNetMarketTest(__file__).main()
