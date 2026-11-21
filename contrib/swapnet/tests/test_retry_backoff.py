"""A swap whose chain calls keep failing backs off on its own; the other swaps keep their one-second tick."""
import pytest

from swapnet.coordinator import Coordinator
from swapnet.errors import SwapError
from swapnet.policy import SafetyPolicy


class Journal:
    def __init__(self, *sids):
        self.rows = {sid: {"stage": "committed"} for sid in sids}
        self.saved = []

    def all(self, principal=None, limit=100):
        return [(sid, 1, dict(s)) for sid, s in self.rows.items()]

    def scheduled(self, *, terminal, after='', limit=4):
        if terminal:
            return []
        rows = [(sid, 1, dict(s)) for sid, s in sorted(self.rows.items())]
        picked = [row for row in rows if row[0] > after]
        if after and len(picked) < limit:
            picked += [row for row in rows if row[0] <= after]
        return picked[:limit]

    def load(self, sid):
        return 1, dict(self.rows[sid])

    def save(self, sid, s, rev):
        self.saved.append((sid, s.get("last_error")))
        return rev + 1


class Clock:
    def __init__(self):
        self.t = 1_900_000_000

    def __call__(self):
        return self.t


def run(ticks, *, fail, sids=("bad", "good"), cap=8, clock=None):
    """fail(sid, t) returns an error code to raise or None. Returns the ticks at which each session ran."""
    clock = clock or Clock()
    journal = Journal(*sids)
    c = Coordinator(journal, None, {}, None, None, None, clock=clock,
                    policy=SafetyPolicy(rpc_retry_max_seconds=cap))
    ran = {sid: [] for sid in sids}

    def tick_one(sid):
        ran[sid].append(clock.t - 1_900_000_000)
        code = fail(sid, clock.t - 1_900_000_000)
        if code:
            raise SwapError(code, "down")
    c.tick_one = tick_one
    for _ in range(ticks):
        c.tick()
        clock.t += 1
    return ran, journal, c


def test_failing_swap_waits_and_the_others_do_not():
    ran, journal, _ = run(40, fail=lambda sid, t: "RPC_UNAVAILABLE" if sid == "bad" else None)
    assert ran["good"] == list(range(40))
    assert ran["bad"] == [0, 1, 3, 7, 15, 23, 31, 39]
    # Every failed run still records its error.
    assert [e["code"] for sid, e in journal.saved if sid == "bad"] == ["RPC_UNAVAILABLE"] * 8


def test_rejected_calls_back_off_too():
    ran, _, _ = run(8, fail=lambda sid, t: "CHAIN_RPC" if sid == "bad" else None)
    assert ran["bad"] == [0, 1, 3, 7]


def test_a_successful_tick_resets_the_delay():
    ran, _, _ = run(30, fail=lambda sid, t: "RPC_UNAVAILABLE" if sid == "bad" and t != 15 else None)
    assert ran["bad"] == [0, 1, 3, 7, 15, 16, 17, 19, 23]


@pytest.mark.parametrize("code", ["STALE_CHAIN", "FINALITY_UNAVAILABLE", "UNSAFE_TIMEOUT"])
def test_other_errors_keep_the_one_second_tick(code):
    ran, _, _ = run(6, fail=lambda sid, t: code if sid == "bad" else None)
    assert ran["bad"] == list(range(6))


def test_another_error_resets_the_delay():
    ran, _, _ = run(10, fail=lambda sid, t: ("STALE_CHAIN" if t == 1 else "RPC_UNAVAILABLE") if sid == "bad" else None)
    assert ran["bad"] == [0, 1, 2, 3, 5, 9]


def test_zero_keeps_the_old_behaviour():
    ran, _, _ = run(6, fail=lambda sid, t: "RPC_UNAVAILABLE", cap=0)
    assert ran["bad"] == ran["good"] == list(range(6))


def test_a_clock_step_back_does_not_park_a_swap():
    clock = Clock()
    ran, _, c = run(1, fail=lambda sid, t: "RPC_UNAVAILABLE" if sid == "bad" else None, clock=clock)
    assert c._retry["bad"][1] == clock.t  # due one second after the failure
    clock.t -= 3600
    c.tick()
    assert ran["bad"] == [0, -3599]


def test_policy_bound():
    assert SafetyPolicy().rpc_retry_max_seconds == 60
    for bad in (-1, 3601, True, 1.5):
        with pytest.raises(SwapError):
            SafetyPolicy(rpc_retry_max_seconds=bad)
