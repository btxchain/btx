"""A newly set EVM policy must carry the pinned creation manifest, as before. A saved policy without one
(v0.34.16 cannot store it) still builds its driver at startup, so existing obligations keep running after an
upgrade; a new trade on it is still refused."""
from types import SimpleNamespace
import pytest
import swapnet.embedded as embedded
from swapnet.deployment import CONTRACT, INIT_HASH, RUNTIME_HASH
from swapnet.embedded import Host
from swapnet.errors import SwapError

ASSET = 'evm:' + '11' * 32 + ':31337:native'
CREATE2 = {'kind': 'create2', 'transaction_id': '00' * 32, 'creation_hash': INIT_HASH,
           'factory': '0x' + '44' * 20, 'factory_runtime_hash': '55' * 32, 'salt': '66' * 32}


def policy(**extra):
    p = {'asset': ASSET, 'rpc_url': 'http://127.0.0.1:8545', 'contract': CONTRACT, 'runtime_hash': RUNTIME_HASH}
    p.update(extra)
    return p


def configure(p, **kw):
    return Host.configure_asset(SimpleNamespace(journal=None, vault=None), p, **kw)


def code(fn):
    with pytest.raises(SwapError) as e:
        fn()
    return e.value.code


def test_new_policy_needs_the_pinned_manifest():
    assert code(lambda: configure(policy())) == 'ASSET_POLICY'
    other = dict(CREATE2, kind='create', creation_hash='22' * 32)
    assert code(lambda: configure(policy(deployment=other))) == 'DEPLOYMENT_CREATION'
    assert code(lambda: configure(policy(contract='0x' + '33' * 20, deployment=CREATE2))) == 'DEPLOYMENT_ADDRESS'


def test_saved_policy_without_manifest_loads_and_refuses_new_trades():
    driver = configure(policy(), saved=True)
    assert driver.contract == CONTRACT
    assert code(driver.new_trade_ready) == 'DEPLOYMENT_REQUIRED'
    other = dict(CREATE2, kind='create', creation_hash='22' * 32)
    assert code(configure(policy(deployment=other), saved=True).new_trade_ready) == 'DEPLOYMENT_CREATION'
    moved = configure(policy(contract='0x' + '33' * 20, deployment=CREATE2), saved=True)
    assert code(moved.new_trade_ready) == 'DEPLOYMENT_ADDRESS'


def test_pinned_manifest_reaches_deployment_check(monkeypatch):
    calls = []
    monkeypatch.setattr(embedded, 'verify_deployment', lambda rpc, contract, manifest: calls.append((contract, manifest)) or {'verified': True})
    for saved in (False, True):
        assert configure(policy(deployment=CREATE2), saved=saved).new_trade_ready() == {'verified': True}
    assert calls == [(CONTRACT, CREATE2), (CONTRACT, CREATE2)]


def test_policy_still_needs_contract_and_runtime_hash():
    p = policy()
    del p['runtime_hash']
    assert code(lambda: configure(p, saved=True)) == 'ASSET_POLICY'
