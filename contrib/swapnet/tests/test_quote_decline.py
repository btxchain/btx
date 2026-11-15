"""A maker that cannot cover a trade tells the taker instead of staying silent."""
from dataclasses import asdict
import pytest
from swapnet.authorization import Principal
from swapnet.policy import Mandate
from test_runtime_recovery_v2 import apps
from test_execution_v2 import A, B

def _market(time):
    return {'sell_asset': A, 'buy_asset': B, 'numerator': '2', 'denominator': '1',
            'maker_fee_atoms': '10', 'max_receive_network_fee_atoms': '100',
            'max_input_atoms': '100000', 'expires_at': time() + 10000}

def _mandate(name, asset, time, total, trade):
    return Mandate(name, asset, total, trade, '1000', time() + 10000, '66' * 32)

def test_exhausted_mandate_declines_and_does_not_quote(apps):
    nodes, time, ledgers, wire, deliver, step = apps
    alice = _mandate('alice', A, time, '10000000', '100000')
    bob = _mandate('bob', B, time, '100', '50')
    mids = {
        'alice': nodes['alice'].rpc(Principal('alice', True), 'createswapmandate', {'mandate': asdict(alice)})['mandate_id'],
        'bob': nodes['bob'].rpc(Principal('bob', True), 'createswapmandate', {'mandate': asdict(bob)})['mandate_id'],
    }
    nodes['bob'].rpc(Principal('bob', True), 'setswapmarket', {
        'market': _market(time), 'mandate_id': mids['bob'],
        'max_local_fee_atoms': '500', 'refund_fee_atoms': '100', 'claim_fee_atoms': '100'})
    rfq = nodes['alice'].rpc(Principal('alice'), 'requestswapquote',
                             {'sell_asset': A, 'buy_asset': B, 'sell_atoms': '10000'})
    for _ in range(3):
        step()
    result = nodes['alice'].rpc(Principal('alice'), 'getswapquotes', {'request_id': rfq['request_id']})
    assert result['quotes'] == []
    assert result['declined']['code'] == 'BUDGET_LIMIT'
    assert not ledgers[A].records and not ledgers[B].records

def test_trade_inside_the_mandate_still_quotes(apps):
    nodes, time, ledgers, wire, deliver, step = apps
    for name, asset in (('alice', A), ('bob', B)):
        mandate = _mandate(name, asset, time, '10000000', '100000')
        mid = nodes[name].rpc(Principal(name, True), 'createswapmandate', {'mandate': asdict(mandate)})['mandate_id']
        if name == 'bob':
            nodes['bob'].rpc(Principal('bob', True), 'setswapmarket', {
                'market': _market(time), 'mandate_id': mid,
                'max_local_fee_atoms': '500', 'refund_fee_atoms': '100', 'claim_fee_atoms': '100'})
    rfq = nodes['alice'].rpc(Principal('alice'), 'requestswapquote',
                             {'sell_asset': A, 'buy_asset': B, 'sell_atoms': '10000'})
    for _ in range(3):
        step()
    result = nodes['alice'].rpc(Principal('alice'), 'getswapquotes', {'request_id': rfq['request_id']})
    assert result['quotes'] and 'declined' not in result
    assert not ledgers[A].records and not ledgers[B].records
