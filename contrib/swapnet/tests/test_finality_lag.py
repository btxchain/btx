"""No new swap starts while an EVM endpoint's finalized block trails the tip too far."""
from dataclasses import asdict

import pytest

from swapnet.assets import Asset
from swapnet.authorization import Principal
from swapnet.errors import SwapError
from swapnet.evm_driver import EVMDriver
from swapnet.policy import Mandate, SafetyPolicy
from test_execution_v2 import A, B
from test_runtime_recovery_v2 import apps  # noqa: F401  (fixture)


def test_policy_limit_defaults_to_one_hour_and_is_validated():
    assert SafetyPolicy().max_evm_finality_lag_seconds == 3600
    for bad in (0, -1, True, 1.5):
        with pytest.raises(SwapError):
            SafetyPolicy(max_evm_finality_lag_seconds=bad)


def _driver(blocks):
    def rpc(method, *params):
        assert method == "eth_getBlockByNumber" and params[1] is False
        return blocks[params[0]]
    asset = Asset("evm", "12" * 32, 84532, "native").id
    return EVMDriver(asset, rpc, None, None, "0x" + "44" * 20, "ab" * 32)


def _block(timestamp):
    return {"hash": "0x" + "cd" * 32, "number": "0x10", "timestamp": hex(timestamp)}


def test_lag_is_tip_time_minus_finalized_time():
    assert _driver({"latest": _block(1_900_016_200), "finalized": _block(1_900_000_000)}).finality_lag() == 16_200
    assert _driver({"latest": _block(1_900_000_000), "finalized": _block(1_900_000_000)}).finality_lag() == 0


def test_lag_needs_a_finalized_block():
    with pytest.raises(SwapError, match="FINALITY_UNAVAILABLE"):
        _driver({"latest": _block(1_900_000_000), "finalized": None}).finality_lag()
    with pytest.raises(SwapError, match="CHAIN_SYNC"):
        _driver({"latest": None, "finalized": _block(1_900_000_000)}).finality_lag()


def _lagging(node, asset, seconds):
    driver = node.drivers[asset]
    driver.family = "evm"
    driver.finality_lag = lambda: seconds


def _setup(nodes, time):
    mids = {}
    for name, asset in (("alice", A), ("bob", B)):
        mandate = Mandate(name, asset, "10000000", "100000", "1000", time() + 10000, "66" * 32)
        mids[name] = nodes[name].rpc(Principal(name, True), "createswapmandate", {"mandate": asdict(mandate)})["mandate_id"]
    market = {"sell_asset": A, "buy_asset": B, "numerator": "2", "denominator": "1", "maker_fee_atoms": "10",
              "max_receive_network_fee_atoms": "100", "max_input_atoms": "100000", "expires_at": time() + 10000}
    nodes["bob"].rpc(Principal("bob", True), "setswapmarket", {
        "market": market, "mandate_id": mids["bob"],
        "max_local_fee_atoms": "500", "refund_fee_atoms": "100", "claim_fee_atoms": "100"})
    return mids


def _quotes(nodes, step):
    rfq = nodes["alice"].rpc(Principal("alice"), "requestswapquote", {"sell_asset": A, "buy_asset": B, "sell_atoms": "10000"})
    for _ in range(3):
        step()
    return rfq["request_id"], nodes["alice"].rpc(Principal("alice"), "getswapquotes", {"request_id": rfq["request_id"]})


def _accept(nodes, quote, mids):
    return nodes["alice"].rpc(Principal("alice"), "acceptswapquote", {
        "quote_id": quote["id"], "mandate_id": mids["alice"], "max_local_fee_atoms": "500", "refund_fee_atoms": "100"})


def test_maker_declines_to_quote_while_lagging(apps):
    nodes, time, ledgers, wire, deliver, step = apps
    _setup(nodes, time)
    _lagging(nodes["bob"], B, 3601)
    _, result = _quotes(nodes, step)
    assert result["quotes"] == []
    assert result["declined"]["code"] == "FINALITY_LAG"
    assert "3601 s" in result["declined"]["message"]


def test_maker_quotes_at_the_limit(apps):
    nodes, time, ledgers, wire, deliver, step = apps
    _setup(nodes, time)
    _lagging(nodes["bob"], B, 3600)
    _, result = _quotes(nodes, step)
    assert result["quotes"] and "declined" not in result


def test_taker_does_not_accept_while_lagging(apps):
    nodes, time, ledgers, wire, deliver, step = apps
    mids = _setup(nodes, time)
    quote = _quotes(nodes, step)[1]["quotes"][0]
    _lagging(nodes["alice"], B, 16_200)
    with pytest.raises(SwapError, match="FINALITY_LAG"):
        _accept(nodes, quote, mids)
    assert nodes["alice"].rpc(Principal("alice", True), "listswaps", {})["swaps"] == []
    assert not ledgers[A].records and not ledgers[B].records


def test_maker_rejects_the_proposal_when_lag_grew_after_the_quote(apps):
    nodes, time, ledgers, wire, deliver, step = apps
    mids = _setup(nodes, time)
    rid, result = _quotes(nodes, step)
    _lagging(nodes["bob"], B, 16_200)
    sid = _accept(nodes, result["quotes"][0], mids)["swap_id"]
    for _ in range(3):
        step()
    assert nodes["alice"].rpc(Principal("alice"), "getswap", {"swap_id": sid})["stage"] == "rejected"
    declined = nodes["alice"].rpc(Principal("alice"), "getswapquotes", {"request_id": rid})["declined"]
    assert declined["code"] == "FINALITY_LAG" and "16200 s" in declined["message"]
    assert nodes["bob"].rpc(Principal("bob", True), "listswaps", {})["swaps"] == []
    assert not ledgers[A].records and not ledgers[B].records
