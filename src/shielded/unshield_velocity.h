// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_UNSHIELD_VELOCITY_H
#define BTX_SHIELDED_UNSHIELD_VELOCITY_H

#include <consensus/amount.h>
#include <serialize.h>

#include <cstddef>
#include <cstdint>
#include <map>

/**
 * Shielded-pool unshield (z->t egress) velocity cap — v0.32.0 defense-in-depth.
 *
 * Sits ALONGSIDE the turnstile (ShieldedPoolBalance, the net-supply firewall) and the C-002 per-tx
 * value/serial bindings (soundness). Those make forgery non-constructible and bound total loss; this
 * bounds the RATE at which value can leave the pool, so a stolen spend key or a future inner-proof
 * regression becomes a slow, observable leak rather than an instant drain.
 *
 * Rule: over any trailing window of `window_blocks` blocks, the total net unshield value must not
 * exceed `cap_bps`/10000 of the shielded pool balance. Implemented as a window SUM over a per-block
 * net-egress log -- a pure function of recent egress, so it is trivially reorg-safe (Undo erases the
 * one entry the connect added) and, because the log is persisted, pruning-safe and identical on every
 * node. Deterministic: height, egress, pool, and params are the only inputs (no wall-clock, no I/O).
 *
 * `net_egress` for a block is the block's net value leaving the pool: max(0, sum of value_balance),
 * where value_balance>0 means value left the pool (an unshield) -- so shields in the same block offset
 * unshields. Inert before the activation height (callers gate on it); self-serve unshield does not
 * exist before C-002 anyway.
 */
class ShieldedUnshieldVelocity
{
public:
    /** Capacity (max net unshield per window) at the given pool balance: cap_bps/10000 of the pool,
     *  optionally floored by a consensus minimum. */
    static CAmount WindowCap(CAmount pool_balance, uint32_t cap_bps, CAmount min_cap = 0);

    /** Record block `height`'s net egress. Stores max(0, net_egress); 0 entries are kept so Undo and
     *  the window boundary stay exact. */
    void RecordBlock(int32_t height, CAmount net_egress);

    /** Reverse RecordBlock for `height` (DisconnectBlock / reorg). */
    void UndoBlock(int32_t height);

    /** Total net egress over the trailing window ending at and including `tip_height`:
     *  sum of entries with (tip_height - window_blocks) < h <= tip_height. */
    [[nodiscard]] CAmount WindowTotal(int32_t tip_height, uint32_t window_blocks) const;

    /** Whether connecting block `tip_height` (already recorded) keeps the window within the cap. */
    [[nodiscard]] bool WithinCap(int32_t tip_height, CAmount pool_balance,
                                 uint32_t cap_bps, uint32_t window_blocks,
                                 CAmount min_cap = 0) const
    {
        return WindowTotal(tip_height, window_blocks) <= WindowCap(pool_balance, cap_bps, min_cap);
    }

    /** Drop entries strictly below `keep_from_height` (bounds the persisted log). Keep a buffer below
     *  the active window so reorgs up to the buffer depth can restore exactly. */
    void Prune(int32_t keep_from_height);

    [[nodiscard]] bool Empty() const { return m_egress.empty(); }
    [[nodiscard]] size_t Size() const { return m_egress.size(); }
    void Clear() { m_egress.clear(); }

    [[nodiscard]] bool operator==(const ShieldedUnshieldVelocity& other) const
    {
        return m_egress == other.m_egress;
    }
    [[nodiscard]] bool operator!=(const ShieldedUnshieldVelocity& other) const
    {
        return !(*this == other);
    }

    SERIALIZE_METHODS(ShieldedUnshieldVelocity, obj) { READWRITE(obj.m_egress); }

private:
    // height -> net egress that left the pool in that block. Sorted for window summation.
    std::map<int32_t, CAmount> m_egress;
};

#endif // BTX_SHIELDED_UNSHIELD_VELOCITY_H
