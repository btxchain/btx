// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/unshield_velocity.h>

#include <algorithm>
#include <limits>

// All amounts are money-range (|x| <= MAX_MONEY ~ 2^51); a window sum of <= ~2^16 blocks each <=
// MAX_MONEY stays under 2^67 -> we saturate at MAX_MONEY rather than overflow int64.

CAmount ShieldedUnshieldVelocity::WindowCap(CAmount pool_balance, uint32_t cap_bps, CAmount min_cap)
{
    const CAmount floor = std::max<CAmount>(0, min_cap);
    if (pool_balance <= 0 || cap_bps == 0) return floor;
    // cap_bps/10000 * pool, split into whole+fractional parts so intermediates stay <= MAX_MONEY.
    const CAmount whole = (pool_balance / 10000) * static_cast<CAmount>(cap_bps);
    const CAmount frac = ((pool_balance % 10000) * static_cast<CAmount>(cap_bps)) / 10000;
    CAmount cap = whole + frac;
    if (cap < 0 || cap > MAX_MONEY) cap = MAX_MONEY;
    return std::max(cap, floor);
}

void ShieldedUnshieldVelocity::RecordBlock(int32_t height, CAmount net_egress)
{
    m_egress[height] = net_egress > 0 ? net_egress : 0;
}

void ShieldedUnshieldVelocity::UndoBlock(int32_t height)
{
    m_egress.erase(height);
}

CAmount ShieldedUnshieldVelocity::WindowTotal(int32_t tip_height, uint32_t window_blocks) const
{
    // Sum entries h in (tip_height - window_blocks, tip_height]. Guard the lower bound against
    // int32 underflow for early heights / large windows.
    const int64_t low64 = static_cast<int64_t>(tip_height) - static_cast<int64_t>(window_blocks);
    const int32_t lower_exclusive =
        low64 < std::numeric_limits<int32_t>::min() ? std::numeric_limits<int32_t>::min()
                                                    : static_cast<int32_t>(low64);
    CAmount total{0};
    // upper_bound(tip_height) is the first element > tip_height; iterate backwards from there.
    for (auto it = m_egress.upper_bound(tip_height); it != m_egress.begin();) {
        --it;
        if (it->first <= lower_exclusive) break; // outside the window
        total += it->second;
        if (total >= MAX_MONEY) return MAX_MONEY; // saturate; cap can be at most MAX_MONEY anyway
    }
    return total;
}

void ShieldedUnshieldVelocity::Prune(int32_t keep_from_height)
{
    m_egress.erase(m_egress.begin(), m_egress.lower_bound(keep_from_height));
}
