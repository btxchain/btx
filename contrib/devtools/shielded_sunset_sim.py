#!/usr/bin/env python3
"""Model post-C002 shielded value flows and a proposed height-125000 sunset.

This is not a consensus implementation. It is a deterministic invariant model
for quickly exercising the value-balance classes found in the C++ probes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

COIN = 100_000_000
C002_HEIGHT = 123_000
SUNSET_HEIGHT = 125_000


@dataclass
class Tx:
    name: str
    height: int
    state_value_balance: int
    tx_value_balance: int
    shielded_outputs: int = 0
    shielded_spends: int = 0
    creates_manifest: bool = False
    manifest: str | None = None
    creates_anchor: bool = False
    anchor: str | None = None
    consumes_anchor: str | None = None
    administrative: bool = False
    fee: int = 0           # the transaction fee component of state_value_balance
    family: str = "v2_send"  # v2_send | recovery | egress | rebalance | ingress | lifecycle


@dataclass
class Ledger:
    pool_balance: int = 0
    manifests: dict[str, int] = field(default_factory=dict)
    anchors: dict[str, int] = field(default_factory=dict)
    consumed_anchors: set[str] = field(default_factory=set)
    enforce_pool_credit_disable: bool = False
    enforce_sunset: bool = False

    def apply(self, tx: Tx) -> None:
        if self.enforce_pool_credit_disable and tx.height >= C002_HEIGHT:
            if tx.state_value_balance < 0:
                raise AssertionError(f"{tx.name}: pool-credit gate rejected shielded credit")
            if tx.creates_manifest:
                raise AssertionError(f"{tx.name}: pool-credit gate rejected new manifest")
            if tx.creates_anchor and not tx.administrative:
                raise AssertionError(f"{tx.name}: pool-credit gate rejected value-bearing anchor")

        if self.enforce_sunset and tx.height >= SUNSET_HEIGHT:
            # Outflow-only sunset (legacy-balance preservation). The ONLY thing allowed is a V2_SEND
            # REAL unshield: value actually LEAVES to transparent, i.e. state_value_balance > fee (since
            # value_balance == transparent_out + fee). A z->z private transfer has state_value_balance ==
            # fee (only the fee leaves) and is rejected. Recovery (re-shield, value_balance == fee, not an
            # outflow, DS-4-unbound), credits, and every other family are also rejected. NB: value_balance
            # > 0 alone is NOT sufficient -- that was the audited bug.
            if tx.family != "v2_send" or tx.state_value_balance <= tx.fee:
                raise AssertionError(f"{tx.name}: sunset rejected non-exit shielded transaction")

        if tx.creates_manifest:
            assert tx.manifest is not None
            if tx.manifest in self.manifests:
                raise AssertionError(f"{tx.name}: duplicate manifest")
            self.manifests[tx.manifest] = tx.height

        if tx.creates_anchor:
            assert tx.anchor is not None
            if tx.anchor in self.anchors:
                raise AssertionError(f"{tx.name}: duplicate anchor")
            self.anchors[tx.anchor] = tx.height

        if tx.consumes_anchor is not None:
            if tx.consumes_anchor not in self.anchors:
                raise AssertionError(f"{tx.name}: missing anchor")
            if tx.consumes_anchor in self.consumed_anchors:
                raise AssertionError(f"{tx.name}: reused anchor")
            self.consumed_anchors.add(tx.consumes_anchor)

        # Mirrors ShieldedPoolBalance::ApplyValueBalance: negative value balance
        # increases the pool, positive value balance decreases it.
        next_balance = self.pool_balance - tx.state_value_balance
        if next_balance < 0:
            raise AssertionError(f"{tx.name}: negative pool")
        self.pool_balance = next_balance


# Constrain-and-preserve framework (see doc/shielded_sunset_125000_plan.md). The model mirrors the
# merged consensus code: DS-5 makes a rebalance pool-neutral (state value_balance == 0); the 123000
# pool-credit gate rejects credits + rollover machinery; the 125000 sunset is the author's full freeze.


def ds5_fixed_rebalance_is_pool_neutral() -> Ledger:
    # (1) DS-5 fix: rebalance state value_balance is the NET of all deltas (= 0 by conservation), not
    # -sum(positive). A net-zero [+7,-7] rebalance no longer credits the pool. (The C++ probe
    # block_rejects_post_c002_repeated_fresh_v2_rebalance... asserts the same: VB == 0, no mint.)
    ledger = Ledger()
    ledger.apply(Tx("ds5_fixed_rebalance", C002_HEIGHT, state_value_balance=0, tx_value_balance=0,
                    shielded_outputs=1, creates_manifest=True, manifest="m1"))
    assert ledger.pool_balance == 0, ledger.pool_balance  # pool-neutral: no mint
    return ledger


def pool_credit_gate_blocks_credits_and_rollover() -> None:
    # (2) At height >= 123000 the pool-credit gate rejects pool credits (negative state value_balance:
    # egress, shield) AND reserve/netting rollover machinery (rebalance via its manifest, value-bearing
    # settlement anchors). DS-1 anchor replay can never re-arm because the model keeps a permanent
    # consumed record. Debits (unshield, value leaving) are NOT rejected -- legacy exits keep working.
    blocked = 0
    for tx in [
        Tx("rebalance", C002_HEIGHT, 0, 0, shielded_outputs=1, creates_manifest=True, manifest="m"),
        Tx("egress_credit", C002_HEIGHT, -(2 * COIN), 0, shielded_outputs=2, consumes_anchor="a"),
        Tx("shield_credit", C002_HEIGHT, -(1 * COIN), 0, shielded_outputs=1),
        Tx("value_bearing_anchor", C002_HEIGHT, 0, 0, creates_anchor=True, anchor="b"),
    ]:
        ledger = Ledger(enforce_pool_credit_disable=True)
        if tx.consumes_anchor:
            ledger.anchors[tx.consumes_anchor] = C002_HEIGHT - 10
        try:
            ledger.apply(tx)
        except AssertionError:
            blocked += 1
    assert blocked == 4

    # A legacy unshield (value LEAVING the pool, positive state value_balance) is ACCEPTED in the
    # [123000, 125000) window and drains the pool -- balances stay recoverable.
    ledger = Ledger(pool_balance=5 * COIN, enforce_pool_credit_disable=True)
    ledger.apply(Tx("legacy_unshield", C002_HEIGHT + 1, state_value_balance=1 * COIN,
                    tx_value_balance=1 * COIN, shielded_spends=1))
    assert ledger.pool_balance == 4 * COIN


def blast_radius_bounded_by_frozen_ceiling() -> None:
    # (3) Monotone clamp: from 123000 the pool only decreases. 100 credit attempts are all rejected;
    # max value ever extractable == the frozen ceiling.
    ceiling = 100 * COIN
    ledger = Ledger(pool_balance=ceiling, enforce_pool_credit_disable=True)
    for i in range(100):
        try:
            ledger.apply(Tx(f"mint_{i}", C002_HEIGHT, -(1_000_000 * COIN), 0, shielded_outputs=1))
            raise SystemExit("monotone clamp failed: a credit was accepted")
        except AssertionError:
            pass
        assert ledger.pool_balance <= ceiling


def settlement_anchor_tombstone_blocks_replay() -> None:
    # (4) DS-1 (modeled): a consumed settlement anchor leaves a PERMANENT record; re-consuming or
    # re-creating it is rejected, so one external settlement cannot be egressed twice.
    ledger = Ledger()
    ledger.apply(Tx("anchor", C002_HEIGHT, 0, 0, creates_anchor=True, anchor="s1"))
    ledger.apply(Tx("egress1", C002_HEIGHT + 7, -(2 * COIN), 0, shielded_outputs=1, consumes_anchor="s1"))
    blocked = 0
    for replay in (
        Tx("replay_consume", C002_HEIGHT + 8, -(2 * COIN), 0, shielded_outputs=1, consumes_anchor="s1"),
        Tx("replay_create", C002_HEIGHT + 8, 0, 0, creates_anchor=True, anchor="s1"),
    ):
        try:
            ledger.apply(replay)
        except AssertionError:
            blocked += 1
    assert blocked == 2


def sunset_outflow_only_preserves_exits() -> None:
    # (5) PRESERVATION: the 125000 sunset is OUTFLOW-ONLY. A real V2_SEND unshield (value LEAVING to
    # transparent: state_value_balance > fee) is ACCEPTED forever and drains the pool, while credits,
    # z->z private transfers (state_value_balance == fee), recovery (re-shield), and rollover/bridge are
    # all rejected. No balance is trapped.
    FEE = 70_000
    rejected = 0
    for tx in [
        Tx("post_sunset_egress_credit", SUNSET_HEIGHT, -(2 * COIN), 0, shielded_outputs=2, family="egress"),
        # z->z private transfer: only the fee leaves -> state_value_balance == fee -> NOT an exit.
        Tx("post_sunset_private_transfer", SUNSET_HEIGHT, FEE, 0, shielded_outputs=1, shielded_spends=1, fee=FEE),
        Tx("post_sunset_rebalance", SUNSET_HEIGHT, 0, 0, shielded_outputs=1, creates_manifest=True, manifest="m", family="rebalance"),
        # recovery re-shields (value_balance == fee) and is DS-4-unbound -> rejected post-sunset.
        Tx("post_sunset_recovery", SUNSET_HEIGHT, FEE, 0, shielded_spends=1, fee=FEE, family="recovery"),
    ]:
        try:
            Ledger(pool_balance=5 * COIN, enforce_sunset=True).apply(tx)
        except AssertionError:
            rejected += 1
    assert rejected == 4  # every non-exit (incl. z->z and recovery) is rejected

    # A REAL unshield -- value_balance = transparent_out + fee > fee -- is ACCEPTED and drains the pool.
    ledger = Ledger(pool_balance=5 * COIN, enforce_sunset=True)
    ledger.apply(Tx("post_sunset_unshield_exit", SUNSET_HEIGHT, state_value_balance=1 * COIN + FEE,
                    tx_value_balance=1 * COIN, shielded_spends=1, fee=FEE))
    assert ledger.pool_balance == 5 * COIN - (1 * COIN + FEE)  # exit preserved -> funds recoverable


def main() -> None:
    ledger = ds5_fixed_rebalance_is_pool_neutral()
    print(f"PASS ds5_rebalance_pool_neutral pool_sats={ledger.pool_balance}")
    pool_credit_gate_blocks_credits_and_rollover()
    print("PASS pool_credit_gate_blocks_credits_and_rollover (legacy unshield still exits)")
    blast_radius_bounded_by_frozen_ceiling()
    print("PASS blast_radius_bounded_by_frozen_ceiling")
    settlement_anchor_tombstone_blocks_replay()
    print("PASS settlement_anchor_tombstone_blocks_replay")
    sunset_outflow_only_preserves_exits()
    print("PASS sunset_outflow_only_preserves_exits (legacy balances never trapped)")


if __name__ == "__main__":
    main()
