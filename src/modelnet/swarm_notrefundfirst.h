// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTREFUNDFIRST_H
#define BTX_MODELNET_SWARM_NOTREFUNDFIRST_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. refund_ready records whether the refund
 * is ready. want_count_funding asks this note to count funding.
 *
 * An unready refund wins over a funding count. This note broadcasts
 * nothing. counted and broadcast stay false on every path.
 */
struct SwarmNotRefundFirst {
    std::string channel_id;
    bool refund_ready{false};
    bool want_count_funding{false};
};

/**
 * Outcome of noting a refund. counted and broadcast stay false on every
 * path. An unready refund wins over a funding count. This note broadcasts
 * nothing.
 */
struct SwarmNotRefundFirstResult {
    std::string code;
    bool counted{false};
    bool broadcast{false};
};

/**
 * Note a refund without counting funding or broadcasting. Order, first
 * match wins: an empty channel_id is CHANNEL. refund_ready false is
 * UNSIGNED even when want_count_funding is false. want_count_funding is
 * UNSIGNED. Otherwise the note is NOTED and err is clear. counted and
 * broadcast stay false on every path. An unready refund wins over a
 * funding count. This note broadcasts nothing.
 */
SwarmNotRefundFirstResult SwarmNoteNotRefundFirst(const SwarmNotRefundFirst& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTREFUNDFIRST_H
