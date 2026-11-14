"""Long-leg planning absorbs one block or ten minutes. The margin check stays strict."""
from dataclasses import replace
import math
import pytest
from swapnet.coordinator import Coordinator
from swapnet.errors import SwapError
from swapnet.policy import ChainClock, Deadline, SafetyPolicy
from conftest import NOW

class Timed:
    def __init__(self, clock):
        self.family = clock.family
        self._clock = clock
    def clock(self):
        return self._clock

def plan(policy, long_clock, short_clock):
    coordinator = Coordinator(None, None, {}, None, None, lambda *args: None, clock=lambda: NOW, policy=policy)
    return coordinator._deadlines(Timed(long_clock), Timed(short_clock))

def test_long_leg_headroom_survives_one_block_and_ten_minutes():
    policy = SafetyPolicy()
    assert policy.settlement_margin_seconds == 7200
    assert policy.planning_headroom_seconds == 600
    with pytest.raises(SwapError, match='INTEGER_RANGE'):
        SafetyPolicy(planning_headroom_seconds=0)
    target = max(21600, policy.reveal_margin_seconds * 4)
    span = policy.settlement_margin_seconds + policy.planning_headroom_seconds

    # Production BTX spacing. One long-leg block still clears the strict margin.
    btx = ChainClock('btx', 1000, NOW, NOW, 45, 180)
    btc = ChainClock('btc', 2000, NOW, NOW, 300, 1200)
    long, short = plan(policy, btx, btc)
    assert short == Deadline('height', btc.height + math.ceil(target / btc.fastest_block_seconds))
    _, worst = short.remaining(btc)
    assert long == Deadline('height', btx.height + math.ceil((worst + span) / btx.fastest_block_seconds))
    one_block = replace(btx, height=btx.height + 1, timestamp=NOW + policy.planning_headroom_seconds)
    assert policy.validate_deadlines(long, short, one_block, btc, NOW)

    # Timestamp long leg. Ten minutes of endpoint skew passes. One more second does not.
    evm = ChainClock('evm', 1, NOW, NOW, 12, 12)
    long, short = plan(policy, evm, evm)
    assert short == Deadline('timestamp', NOW + target)
    assert long == Deadline('timestamp', NOW + target + span)
    assert policy.validate_deadlines(long, short, replace(evm, timestamp=NOW + policy.planning_headroom_seconds), evm, NOW)
    with pytest.raises(SwapError, match='UNSAFE_TIMEOUT'):
        policy.validate_deadlines(long, short, replace(evm, timestamp=NOW + policy.planning_headroom_seconds + 1), evm, NOW)

    # Height budget that divides evenly, so the headroom boundary is one block wide.
    exact = ChainClock('btx', 1000, NOW, NOW, 60, 120)
    long, short = plan(policy, exact, evm)
    blocks = (target + span) // exact.fastest_block_seconds
    assert short == Deadline('timestamp', NOW + target)
    assert long == Deadline('height', exact.height + blocks)
    within = policy.planning_headroom_seconds // exact.fastest_block_seconds
    assert policy.validate_deadlines(long, short, replace(exact, height=exact.height + within), evm, NOW)
    with pytest.raises(SwapError, match='UNSAFE_TIMEOUT'):
        policy.validate_deadlines(long, short, replace(exact, height=exact.height + within + 1), evm, NOW)

    # validate_deadlines does not treat a planned pair as a waiver of the 7200s margin.
    bare_long = Deadline('timestamp', NOW + target + policy.settlement_margin_seconds)
    bare_short = Deadline('timestamp', NOW + target)
    assert policy.validate_deadlines(bare_long, bare_short, evm, evm, NOW)
    with pytest.raises(SwapError, match='UNSAFE_TIMEOUT'):
        policy.validate_deadlines(bare_long, bare_short, replace(evm, timestamp=NOW + 1), evm, NOW)
