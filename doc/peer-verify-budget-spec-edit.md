# Spec Edits for `nMatMulPeerVerifyBudgetPerMin` Rationale

This document contains the exact edits to apply to
`doc/btx-matmul-pow-spec.md` to add explicit justification for the
`nMatMulPeerVerifyBudgetPerMin` default value of 8.

---

## Edit 1: Add rationale comments to Section 5.1 parameter declaration

**Location**: Section 5.1 (`New Fields in Consensus::Params`), line 649.

**old_string**:

```
uint32_t nMatMulPeerVerifyBudgetPerMin{8};   // Max expensive verifications per peer per minute
uint32_t nMatMulPhase2FailBanThreshold{3};   // Ban after N Phase 2 failures within 24h from same peer
```

**new_string**:

```
uint32_t nMatMulPeerVerifyBudgetPerMin{8};   // Max expensive verifications per peer per minute
                                              //
                                              // Rationale for default value (8):
                                              //   Steady state (90s blocks): ~0.67 blocks/min arrival rate;
                                              //     budget of 8 provides ~12x headroom for burst absorption
                                              //     (Poisson clustering, small reorgs, reconnection catch-up).
                                              //   Fast phase (0.25s blocks): ~240 blocks/min; budget of 8 naturally
                                              //     enforces Phase 2 deferral (§10.3.1) at the rate-limit layer
                                              //     without special-case scheduling code.
                                              //   Attack bound: worst case 8 × 2.0s = 16s CPU/min per attacker
                                              //     peer (~27% single-core on older hardware); bounded further
                                              //     by nMatMulMaxPendingVerifications=4 concurrency cap and
                                              //     nMatMulPhase2FailBanThreshold=3 (ban after 3 failures).
                                              //   IBD: budget-limited to 8 verifications/min from the IBD peer;
                                              //     operators MAY raise for faster Phase 2 catch-up on dedicated
                                              //     hardware (see §12.4 tuning notes).
uint32_t nMatMulPhase2FailBanThreshold{3};   // Ban after N Phase 2 failures within 24h from same peer
```

---

## Edit 2: Add rationale paragraph after PeerVerificationBudget struct in Section 10.2.1

**Location**: Section 10.2.1 (`Peer Verification State`), after the closing
`};` of the `PeerVerificationBudget` struct (line 2771), before Section 10.2.2.

**old_string**:

```
};
```

(The `};` that closes the `PeerVerificationBudget` struct at line 2771.)

Because `};` appears multiple times in the file, the unique context for this
edit is the full surrounding block:

**old_string** (with context for uniqueness):

```
    // Reset rolling counter if 24h have elapsed since first failure in window
    void MaybeResetPhase2Window() {
        if (phase2_failures > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::hours>(
                now - phase2_first_failure_time);
            if (elapsed.count() >= 24) {
                phase2_failures = 0;
                // Window will be re-anchored on next failure
            }
        }
    }
};
```

**new_string**:

```
    // Reset rolling counter if 24h have elapsed since first failure in window
    void MaybeResetPhase2Window() {
        if (phase2_failures > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::hours>(
                now - phase2_first_failure_time);
            if (elapsed.count() >= 24) {
                phase2_failures = 0;
                // Window will be re-anchored on next failure
            }
        }
    }
};
```

**Default Value Justification for `nMatMulPeerVerifyBudgetPerMin` (8)**:

The per-peer budget, global concurrency cap, and graduated punishment form a
three-layer defense against verification-cost DoS attacks:

| Layer | Parameter | Default | Role |
|-------|-----------|---------|------|
| Per-peer soft limit | `nMatMulPeerVerifyBudgetPerMin` | 8 | Caps the rate at which any single peer can submit blocks for expensive Phase 2 verification. Excess blocks are queued, not dropped. |
| Global hard limit | `nMatMulMaxPendingVerifications` | 4 | Caps the number of Phase 2 verifications executing concurrently across all peers. This is the ultimate CPU-time bound. |
| Per-peer punitive limit | `nMatMulPhase2FailBanThreshold` | 3 | Permanently removes peers that repeatedly send Phase-2-invalid blocks. Bounds total attacker impact to `3 * T_phase2` seconds of CPU per Sybil peer. |

**Why 8**: At steady-state (90s blocks, ~0.67 blocks/min), a budget of 8
provides ~12x headroom above normal demand, absorbing Poisson burst arrivals
and small reorgs without throttling honest peers. During the fast-mining phase
(0.25s blocks, ~240 blocks/min), the budget naturally limits Phase 2 throughput to
~8/min per peer, which enforces the Phase 2 deferral policy described in
Section 10.3.1 at the rate-limiting layer without requiring height-dependent
scheduling logic. Under attack, worst-case CPU cost per malicious peer is
8 * 2.0s = 16 seconds per minute (~27% of a single core on older hardware),
and the concurrency cap of 4 provides the hard ceiling regardless of peer count.

**Tuning guidance**: Operators running dedicated IBD sync nodes may raise the
budget (e.g., to 32-64) to allow the concurrency limit rather than the per-peer
budget to be the throughput bottleneck, reducing Phase 2 catch-up time from
~125 minutes to ~25 minutes. Resource-constrained nodes (e.g., Raspberry Pi)
may lower the budget to 4 to reduce maximum per-peer CPU impact.

---

The exact old_string and new_string for this edit require special care because
the paragraph is being **inserted** between the struct closing and the next
section header. The full edit with unique context:

**old_string**:

```
            }
        }
    }
};
```

#### 10.2.2 Graduated Punishment Model

**new_string**:

```
            }
        }
    }
};
```

**Default value justification for `nMatMulPeerVerifyBudgetPerMin` (8)**:

The per-peer budget, global concurrency cap, and graduated punishment form a
three-layer defense against verification-cost DoS attacks:

| Layer | Parameter | Default | Role |
|-------|-----------|---------|------|
| Per-peer soft limit | `nMatMulPeerVerifyBudgetPerMin` | 8 | Caps the rate at which any single peer can submit blocks for expensive Phase 2 verification. Excess blocks are queued, not dropped. |
| Global hard limit | `nMatMulMaxPendingVerifications` | 4 | Caps the number of Phase 2 verifications executing concurrently across all peers. This is the ultimate CPU-time bound. |
| Per-peer punitive limit | `nMatMulPhase2FailBanThreshold` | 3 | Permanently removes peers that repeatedly send Phase-2-invalid blocks. Bounds total attacker impact to `3 * T_phase2` seconds of CPU per Sybil peer. |

**Why 8**: At steady-state (90s blocks, ~0.67 blocks/min), a budget of 8
provides ~12x headroom above normal demand, absorbing Poisson burst arrivals
and small reorgs without throttling honest peers. During the fast-mining phase
(0.25s blocks, ~240 blocks/min), the budget naturally limits Phase 2 throughput to
~8/min per peer, which enforces the Phase 2 deferral policy (Section 10.3.1)
at the rate-limiting layer without requiring height-dependent scheduling logic.
Under attack, worst-case CPU cost per malicious peer is 8 * 2.0s = 16 seconds
per minute (~27% of a single core on older hardware), and the concurrency cap
of 4 provides the hard ceiling regardless of peer count.

**Tuning guidance**: Operators running dedicated IBD sync nodes may raise the
budget (e.g., to 32--64) to allow the concurrency limit rather than the
per-peer budget to be the throughput bottleneck, reducing Phase 2 catch-up
time from ~125 minutes to ~25 minutes for 1000 blocks. Resource-constrained
nodes (e.g., Raspberry Pi 4) may lower the budget to 4 to reduce maximum
per-peer CPU impact to ~24s/min. High-connectivity nodes (>50 peers) may
lower to 4--6 to reduce aggregate demand submission rate.

#### 10.2.2 Graduated Punishment Model

---

## Edit 3 (Optional): Add IBD tuning note to Section 12.4

**Location**: Section 12.4.1 or 12.4.2, after the IBD time estimate.

This edit is recommended to resolve the discrepancy between the ~25 minute IBD
Phase 2 estimate in Section 12.4 and the budget-limited reality of ~125 minutes
at the default budget of 8 from a single IBD peer.

**old_string**:

```
**Estimated IBD time** (10,000-block chain, mid-range CPU):
- Headers + Phase 1: ~seconds
- UTXO + transaction validation: ~minutes
- Phase 2 for post-assumevalid window (last 1000): ~25 minutes
- Total: **~30 minutes** (dominated by Phase 2 catch-up)
```

**new_string**:

```
**Estimated IBD time** (10,000-block chain, mid-range CPU):
- Headers + Phase 1: ~seconds
- UTXO + transaction validation: ~minutes
- Phase 2 for post-assumevalid window (last 1000): ~25 minutes
  (assumes concurrency-limited throughput; see note below)
- Total: **~30 minutes** (dominated by Phase 2 catch-up)

> **IBD tuning note**: The ~25 minute estimate assumes the
> `nMatMulMaxPendingVerifications` concurrency cap (4) is the throughput
> bottleneck. With the default `nMatMulPeerVerifyBudgetPerMin` of 8 and a
> single IBD peer, the per-peer budget is the binding constraint: 8
> verifications/min yields ~125 minutes for 1000 blocks. To achieve the ~25
> minute estimate, operators syncing from a single peer should raise the
> per-peer budget to 32--64 (e.g., `-matmulpeerverifybudget=64`). With
> multiple IBD peers serving different block ranges, the default budget of 8
> per peer is typically sufficient as the aggregate throughput from all peers
> exceeds the concurrency cap.
```

---

## Summary of Edits

| # | Section | Type | Description |
|---|---------|------|-------------|
| 1 | 5.1 | Inline comment expansion | Add rationale comments after `nMatMulPeerVerifyBudgetPerMin` declaration |
| 2 | 10.2.1 | New paragraph | Add "Default value justification" block with three-layer defense table, "Why 8" analysis, and tuning guidance |
| 3 | 12.4.1 | Addendum | Add IBD tuning note clarifying budget-vs-concurrency bottleneck for single-peer sync |

Edits 1 and 2 are **required** to address the flagged gap. Edit 3 is
**recommended** to maintain consistency between the IBD time estimates and
the rate-limiting parameters.
