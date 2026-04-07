# `nMatMulPeerVerifyBudgetPerMin` Default Value Analysis

## Parameter Definition

`nMatMulPeerVerifyBudgetPerMin` (default: **8**) controls the maximum number of
Phase 2 (expensive transcript recomputation) verifications that a node will
perform for blocks received from any single peer within a one-minute rolling
window. Blocks arriving from a peer that has exhausted its budget are queued
rather than verified immediately. This is a soft, per-peer rate limit; the hard,
global concurrency cap is `nMatMulMaxPendingVerifications` (default: 4).

---

## 1. Steady-State Analysis (90-second blocks)

**Block arrival rate**: At 90-second target spacing, approximately 0.67 blocks
per minute arrive from the network as a whole. In a well-connected network
with 8 outbound peers, a node typically receives each new block from multiple
peers near-simultaneously, but only the first valid arrival triggers Phase 2.

**Per-peer demand under normal conditions**: A single honest peer relays at
most ~0.4 new blocks per minute. A budget of 8 provides 20x headroom above the
expected single-peer relay rate. This headroom accommodates:

- Short-term bursts when multiple blocks are found in quick succession (Poisson
  clustering: the probability of 8+ blocks in a single minute at lambda=0.4 is
  astronomically small, ~1.6e-8).
- Small reorgs where a peer sends 2-3 blocks in rapid succession.
- Block relay after a node reconnects and the peer sends a few recent blocks.

**Interaction with `nMatMulMaxPendingVerifications=4`**: Even if all 8 per-peer
budget slots were consumed simultaneously, only 4 Phase 2 verifications run
concurrently. The remaining 4 queue. At 0.5-2.0 seconds per verification,
draining 8 queued verifications takes 4-16 seconds -- well within the 90-second
block interval.

**Conclusion (steady state)**: A budget of 8 is more than sufficient for honest
operation and provides comfortable headroom without any risk of stalling valid
chain synchronization.

---

## 2. Fast-Phase Analysis (0.25-second blocks, h < 50,000)

**Block arrival rate**: At 0.25-second target spacing, up to 240 blocks per minute
arrive. A single peer forwarding the full chain produces up to 240 blocks/min.

**Budget impact**: With a budget of 8, only 8 out of ~240 fast-phase blocks
from any single peer trigger immediate Phase 2 verification per minute. The
remaining ~232 blocks are either:

- Queued in the deferred Phase 2 verification queue (bounded by
  `nMatMulMaxPendingVerifications * FAST_PHASE_QUEUE_MULTIPLIER`, suggested
  depth: 200 blocks), or
- Phase 1 verified only, with Phase 2 deferred until the queue drains.

**Is this acceptable?** Yes. The specification (Section 10.3.1) explicitly
states that Phase 2 MAY be deferred during the fast-mining phase. The per-peer
budget of 8 naturally enforces this deferral at the rate-limiting layer. The
interaction is well-aligned:

- Phase 1 is applied immediately to every block (microsecond cost, no budget).
- Phase 2 deferral is the expected behavior during the fast phase.
- The budget prevents any single peer from monopolizing the verification queue.
- After transition to 90-second blocks at height 50,000, the deferred queue
  drains at ~75-300 deferred blocks per block interval (Section 10.3.1 point 3).

**Conclusion (fast phase)**: The budget of 8 produces the correct behavior:
it allows meaningful Phase 2 sampling during the fast phase while naturally
enforcing the deferral policy without special-case code.

---

## 3. IBD (Initial Block Download) Analysis

**IBD model**: During IBD, a node downloads blocks from one or a few peers at
high speed. A single peer may relay thousands of blocks in rapid succession.

**Budget impact during IBD**: A budget of 8 means at most 8 Phase 2
verifications per minute from the IBD peer. However, this interaction is
largely academic because:

1. **`assumevalid` dominates**: During IBD, blocks at or below the
   `defaultAssumeValid` checkpoint skip Phase 2 entirely (Section 10.3,
   Section 12.4). The per-peer budget is irrelevant for these blocks.

2. **Validation window bounds Phase 2 scope**: Only the last
   `nMatMulValidationWindow` blocks (default: 1000) above `assumevalid`
   require Phase 2 during IBD (Section 12.3).

3. **Effective IBD Phase 2 rate**: For the ~1000 blocks requiring Phase 2
   post-`assumevalid`, a budget of 8/min means the node processes Phase 2 at
   8 blocks/min = ~2 minutes per batch of 8. Total Phase 2 IBD time for
   1000 blocks: ~125 minutes at budget-limited rate.

   However, the per-peer budget should not be the bottleneck during IBD. The
   actual bottleneck is `nMatMulMaxPendingVerifications=4` and the per-block
   verification time (0.5-2.0s). With 4 concurrent verifications at ~1.5s
   each, throughput is ~160 blocks/min, which exceeds the per-peer budget.

   **Implication**: During IBD, the per-peer budget (8/min) is the binding
   constraint, not the concurrency limit. This is intentional: it prevents
   an IBD peer from consuming the node's full verification capacity,
   leaving room for tip-block verification from other peers.

   At 8 verifications/min with ~1.5s each, IBD Phase 2 for 1000 blocks
   takes ~125 minutes. At 0.5s each (modern CPU), it takes ~125 minutes
   (still budget-bound, not CPU-bound).

4. **Operator tuning opportunity**: Operators performing IBD on dedicated
   hardware with no other peers may wish to raise the per-peer budget to
   accelerate Phase 2 catch-up. A value of 32 or 64 would allow the
   concurrency limit to become the binding constraint instead, reducing
   IBD Phase 2 time to ~25 minutes (matching the estimate in Section 12.4).

**Conclusion (IBD)**: The default of 8 is conservative during IBD and may
extend Phase 2 catch-up time beyond the estimates in Section 12.4 (which
assume concurrency-limited, not budget-limited, throughput). This is
acceptable for normal operation where the node has active peers, but
operators should be aware that raising the budget during IBD can
significantly reduce sync time. See "Tuning Guidance" below.

**Recommendation**: Add a note in Section 12.4 that IBD Phase 2 time
estimates assume the per-peer budget is not the binding constraint (e.g.,
the operator has raised it or has multiple peers serving recent blocks).

---

## 4. Attack Analysis

**Attack model**: An adversary connects to the victim node and sends blocks
that pass Phase 1 (valid header: `matmul_digest < target`, dimension in
bounds, non-null seeds) but fail Phase 2 (incorrect transcript). Each such
block wastes 0.5-2.0 seconds of CPU on the victim.

**Per-peer CPU cost with budget of 8**:

| Hardware | Phase 2 time | Max CPU/min from one peer (budget=8) | CPU utilization (single core) |
|----------|-------------|--------------------------------------|-------------------------------|
| Modern x86 (Zen 4) | ~0.5s | 8 * 0.5s = 4s | ~6.7% |
| Modern ARM (Apple M2) | ~0.7s | 8 * 0.7s = 5.6s | ~9.3% |
| Older x86 (Haswell) | ~1.5-2.0s | 8 * 2.0s = 16s | ~26.7% |
| Low-end ARM (RPi 4) | ~4-6s | 8 * 6s = 48s | ~80% |

**Concurrent cap interaction**: `nMatMulMaxPendingVerifications=4` ensures
that at most 4 Phase 2 verifications execute simultaneously, regardless of
how many peers have remaining budget. Maximum instantaneous CPU cost:

- Modern x86: 4 * 0.5s = 2s of CPU at any instant
- Older x86: 4 * 2.0s = 8s of CPU at any instant

Since verification runs on a dedicated thread pool (or the validation thread),
this caps the CPU impact to at most 4 cores.

**Multi-peer amplification**: With `n` attacker-controlled peers, each
sending at budget rate, the total Phase 2 demand is `8n` per minute. But the
concurrency cap of 4 is the hard limit. With 8 attacker peers:

- Demand: 64 verifications/min
- Actual throughput: at most 4 concurrent * (60s / 2.0s per verification) =
  120 verifications/min on slow hardware, 480/min on fast hardware.
- So 64/min is within throughput capacity on any hardware.
- CPU utilization: 64 * 2.0s = 128s of CPU per minute = ~2.13 core-minutes,
  but capped at 4 concurrent = effectively 4 cores at 100%.

Wait -- the concurrency limit is 4, not 4 cores. The 4 concurrent
verifications consume 4 threads. If the node has 4+ cores, the verification
threads compete with block relay, mempool, etc. On a 4-core machine,
sustained attack maxes out at 4 cores * 100% = all cores busy with
verification, starving other node functions.

**Revised analysis**: The critical constraint is:

- Budget of 8 per peer caps *demand submission rate* per peer.
- Concurrency of 4 caps *execution rate* globally.
- If demand exceeds execution capacity, the queue grows.
- The queue is bounded (Section 10.3.1: 200 blocks during fast phase;
  during steady state, queue depth is implicitly bounded by the per-peer
  budget * number of peers).

With 8 connected attacker peers at budget=8, the queue receives 64 blocks/min.
With 4 concurrent verifications at 2s each, throughput = 120/min. Queue drains
faster than it fills. No queue overflow.

With 32 attacker connections (Bitcoin Core default max inbound = 125) at
budget=8: 256 blocks/min demand. At 4 concurrent * 2s = 120/min throughput,
the queue grows at 136/min. This is manageable because:

1. Each failed Phase 2 triggers graduated punishment (disconnect at 1st fail,
   discourage at 2nd, ban at 3rd within 24h per Section 10.2.2).
2. After 3 Phase 2 failures, the peer is banned. So each attacker peer is
   banned after contributing at most 3 invalid blocks to the queue.
3. 32 attacker peers * 3 failures each = 96 Phase 2 verifications before all
   are banned. At 120/min throughput, this clears in under 1 minute.
4. Total CPU wasted: 96 * 2s = 192s = ~3.2 minutes of single-core time,
   spread across 4 concurrent threads = ~48 seconds wall time.

**Conclusion (attack)**: The budget of 8 is well-bounded. The actual attack
surface is limited by the Phase 2 failure ban threshold (3 failures per peer
before ban), not by the per-minute budget. An attacker with `n` Sybil peers
wastes at most `3n * T_phase2` seconds of CPU before all peers are banned.
The per-peer budget prevents any single peer from exceeding 8 verifications
per minute even before the failure threshold kicks in.

---

## 5. Multi-Peer Interaction Analysis

The three limits form a layered defense:

```
Layer 1 (per-peer, soft):  nMatMulPeerVerifyBudgetPerMin = 8
    Prevents any single peer from submitting more than 8 expensive
    verifications per minute. Excess blocks are queued, not verified.

Layer 2 (global, hard):    nMatMulMaxPendingVerifications = 4
    Caps concurrent Phase 2 execution across ALL peers. Even if 8 peers
    each have remaining budget, only 4 verifications run simultaneously.

Layer 3 (per-peer, punitive): nMatMulPhase2FailBanThreshold = 3
    Permanently removes peers that repeatedly send Phase-2-invalid blocks.
    This is the ultimate bound on total attacker impact.
```

**Interaction under honest conditions (steady state)**:

- 8 peers, each relaying ~0.4 blocks/min = ~3.2 total blocks/min.
- Most are duplicates of the same block; only 1 triggers Phase 2.
- Budget of 8 per peer is never approached.
- Concurrency of 4 is never approached.

**Interaction under honest conditions (fast phase)**:

- 8 peers, each relaying ~240 blocks/min (but mostly duplicates).
- Unique blocks: ~240/min. Per-peer budget: 8/min. But since peers relay
  the *same* blocks, duplicate detection suppresses most Phase 2 triggers.
- Effective Phase 2 demand: ~8-16/min (unique blocks where verification
  hasn't already been triggered by another peer's relay).
- Concurrency of 4 handles this easily.

**Interaction under attack (mixed honest + malicious)**:

- 4 honest peers relay valid blocks at ~0.4/min each.
- 4 attacker peers send invalid blocks at budget rate (8/min each = 32/min).
- Concurrency of 4 prioritizes by total work (Section 10.3); honest blocks
  from the best-work chain take priority.
- Attacker blocks verified at remaining capacity; each failure triggers
  graduated punishment.
- After 3 failures per attacker peer (12 total verifications, ~24s CPU),
  all attackers banned. Honest peers unaffected.

---

## 6. Recommendation

**The default value of 8 is correct and well-justified.** The analysis shows:

| Scenario | Budget=8 behavior | Acceptable? |
|----------|-------------------|-------------|
| Steady-state honest relay | 20x headroom above demand | Yes |
| Fast-phase honest relay | Natural Phase 2 deferral | Yes (by design) |
| IBD Phase 2 catch-up | Budget-limited to ~125 min for 1000 blocks | Acceptable; tunable |
| Single-peer attack | Max ~27% CPU (older hardware) | Yes |
| Multi-peer Sybil attack | Bounded by ban threshold; ~3.2 min CPU total | Yes |

A lower value (e.g., 4) would still work for steady-state but would:
- Further slow IBD Phase 2 catch-up.
- Reduce Phase 2 sampling during the fast phase.

A higher value (e.g., 16) would:
- Speed up IBD Phase 2 catch-up.
- Increase per-peer attack surface (16 * 2s = 32s CPU/min = ~53% on older hardware).
- Still be bounded by the concurrency cap of 4.

The value of 8 strikes the correct balance: it is generous enough for all
honest scenarios, conservative enough for attack defense on older hardware,
and naturally produces the desired Phase 2 deferral behavior during the fast
phase without requiring special-case scheduling code.

---

## 7. Specification Text

### 7.1 Rationale Block for Section 5.1

The following rationale should be added as inline comments after the
`nMatMulPeerVerifyBudgetPerMin` declaration in Section 5.1:

```cpp
uint32_t nMatMulPeerVerifyBudgetPerMin{8};   // Max expensive verifications per peer per minute
                                              //
                                              // Rationale for default value (8):
                                              //   Steady state (90s blocks): ~0.67 blocks/min arrival rate;
                                              //     budget of 8 provides ~12x headroom for burst absorption
                                              //     (Poisson clustering, small reorgs, reconnection catch-up).
                                              //   Fast phase (0.25s blocks): ~240 blocks/min; budget of 8 naturally
                                              //     enforces Phase 2 deferral (section 10.3.1) at the rate-limit
                                              //     layer without special-case scheduling code.
                                              //   Attack bound: worst case 8 * 2.0s = 16s CPU/min per attacker
                                              //     peer (~27% single-core on older hardware); bounded further
                                              //     by nMatMulMaxPendingVerifications=4 concurrency cap and
                                              //     nMatMulPhase2FailBanThreshold=3 (ban after 3 failures).
                                              //   IBD: budget-limited to 8 verifications/min from the IBD peer;
                                              //     operators MAY raise for faster Phase 2 catch-up on dedicated
                                              //     hardware (see section 12.4 tuning notes).
```

### 7.2 Justification Text for Section 10.2.1

A rationale paragraph should be added after the `PeerVerificationBudget` struct
definition in Section 10.2.1, explaining the interaction between the three
limiting mechanisms.

### 7.3 Tuning Guidance

The following guidance should be provided for operators:

| Scenario | Suggested `nMatMulPeerVerifyBudgetPerMin` | Rationale |
|----------|------------------------------------------|-----------|
| Normal operation (mainnet) | **8** (default) | Sufficient for honest relay; bounded for attack defense |
| Dedicated IBD sync node | **32-64** | Allows concurrency limit (not budget) to be the bottleneck; reduces Phase 2 catch-up from ~125 min to ~25 min |
| Resource-constrained node (RPi, low-end ARM) | **4** | Reduces max per-peer CPU to ~24s/min; accepts slower IBD |
| High-connectivity node (>50 peers) | **4-6** | Reduces aggregate demand submission rate across many peers |
| Testnet / regtest | **8** (default) | Budget is less critical; Phase 2 failures never ban on test networks |

### 7.4 Fast-Phase-Specific Guidance

During the fast-mining phase (h < 50,000, 0.25-second blocks), the per-peer
budget is the primary mechanism that controls Phase 2 verification throughput.
Operators should understand that:

1. **Phase 2 will fall behind during the fast phase.** This is by design
   (Section 10.3.1). The per-peer budget of 8 allows ~8 Phase 2
   verifications per minute per peer, while ~240 blocks per minute arrive.
   The remaining blocks accumulate in the deferred verification queue.

2. **Raising the budget during the fast phase is NOT recommended.** A higher
   budget increases CPU utilization without meaningful security benefit,
   because Phase 1 already validates every block immediately and the fast
   phase represents only 4.76% of total supply.

3. **The deferred queue drains after transition.** At height 50,000, block
   time increases to 90 seconds. The verifier processes ~75-300 deferred
   blocks per block interval, catching up within minutes.

4. **GPU-accelerated nodes are unaffected.** With Phase 2 time < 0.1s, even
   a budget of 8 allows the node to verify every fast-phase block in
   real time. The budget is not the bottleneck for GPU nodes.
