// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MATMUL_VERIFIED_FORK_PARENT_H
#define BITCOIN_NODE_MATMUL_VERIFIED_FORK_PARENT_H

#include <cstddef>

namespace node {

/**
 * Issue #146: a retained child can sit forever after its parent is
 * ExactReplay-verified off the active chain. BlockConnected does not fire
 * for that parent, so the only historical wake never arrives.
 *
 * These predicates are the isolated gate. They do not accept a block, do
 * not bypass PoW / UTXO / script / PARK, and do not change RB-16
 * acquisition, GETDATA, or the #163 progress lane. The caller gathers
 * chain facts under cs_main, drops that lock, then WakeRetryOnce(
 * VERIFIED_FORK_PARENT) so the lifecycle mutex is never taken with
 * cs_main.
 */
struct VerifiedForkParentWakeView {
    bool consensus_mode{false};
    bool strictly_heavier_competing{false};
    bool next_needed_is_priority{false};
    bool parent_off_active_chain{false};
    bool ancestor_prefix_ready{false};
    bool best_header_failed{false};
    bool branch_parked{false};
    bool processed_root_parked{false};
};

[[nodiscard]] inline bool ShouldWakeRetainedChildForVerifiedForkParent(
    const VerifiedForkParentWakeView& v)
{
    return v.consensus_mode &&
           v.strictly_heavier_competing &&
           v.next_needed_is_priority &&
           v.parent_off_active_chain &&
           v.ancestor_prefix_ready &&
           !v.best_header_failed &&
           !v.branch_parked &&
           !v.processed_root_parked;
}

/** One ancestor of the retained child, parent-first toward genesis. */
struct AncestorPrefixStep {
    bool on_active_chain{false};
    bool have_data{false};
    bool exact_replay{false};
    bool failed{false};
};

/**
 * The off-chain ancestor prefix down to (but not including) the active
 * chain must be HAVE_DATA + EXACT_REPLAY with no FAILED. The first
 * active-chain ancestor is the fork root and ends the walk. An empty
 * walk, a FAILED bit, or never reaching the active chain is not ready.
 */
[[nodiscard]] inline bool AncestorPrefixExactReplayReady(
    const AncestorPrefixStep* steps, size_t n)
{
    if (steps == nullptr || n == 0) return false;
    bool saw_off_chain{false};
    for (size_t i = 0; i < n; ++i) {
        if (steps[i].failed) return false;
        if (steps[i].on_active_chain) return saw_off_chain;
        if (!steps[i].have_data || !steps[i].exact_replay) return false;
        saw_off_chain = true;
    }
    return false;
}

} // namespace node

#endif // BITCOIN_NODE_MATMUL_VERIFIED_FORK_PARENT_H
