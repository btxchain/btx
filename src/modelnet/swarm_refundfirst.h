// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REFUNDFIRST_H
#define BTX_MODELNET_SWARM_REFUNDFIRST_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. refund_signed records whether a refund
 * is already signed. want_count_funding asks this note to count funding.
 *
 * A refund must be signed before funding counts. This note does not count
 * funding, does not sign, and does not broadcast. counted and broadcast
 * stay false. No hostnames or IPs are used.
 */
struct SwarmRefundFirst {
    std::string channel_id;
    bool refund_signed{false};
    bool want_count_funding{false};
};

/**
 * Outcome of noting refund-before-funding. counted and broadcast stay
 * false: nothing is signed and nothing is broadcast.
 */
struct SwarmRefundFirstResult {
    bool counted{false};
    bool broadcast{false};
    std::string code;
};

/**
 * Note that a refund must be signed before funding counts.
 * Order, first match wins:
 * an empty channel_id is FUND. Both counted and broadcast are false and
 * err is FUND.
 * A refund that is not signed is UNSIGNED, even when want_count_funding
 * is true. Both counted and broadcast are false and err is UNSIGNED.
 * want_count_funding is HELD. Both counted and broadcast are false and
 * err is cleared. A signed refund still does not make this note count
 * funding.
 * Otherwise the note is NOTED. Both counted and broadcast are false and
 * err is cleared.
 * counted and broadcast stay false. Nothing is signed and nothing is
 * broadcast.
 */
SwarmRefundFirstResult SwarmNoteRefundFirst(const SwarmRefundFirst& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REFUNDFIRST_H
