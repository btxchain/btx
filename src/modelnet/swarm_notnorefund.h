// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREFUND_H
#define BTX_MODELNET_SWARM_NOTNOREFUND_H

#include <string>

namespace modelnet {

/**
 * A local note about one channel. refund_signed says the refund is
 * signed. want_count_funding asks this note to count funding.
 *
 * Funding is not counted before the refund is signed.
 * counted and broadcast stay false on every path.
 */
struct SwarmNotNoRefund {
    std::string channel_id;
    bool refund_signed{false};
    bool want_count_funding{false};
};

/**
 * Outcome of noting a channel. counted and broadcast stay false on every
 * path: funding is not counted before the refund is signed.
 */
struct SwarmNotNoRefundResult {
    std::string code;
    bool counted{false};
    bool broadcast{false};
};

/**
 * Note a channel without counting funding or broadcasting it.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * refund_signed false is UNSIGNED even when want_count_funding is false.
 * want_count_funding is UNSIGNED. Otherwise the note is NOTED and err is
 * cleared. counted and broadcast stay false on every path. Funding is
 * not counted before the refund is signed.
 */
SwarmNotNoRefundResult SwarmNoteNotNoRefund(const SwarmNotNoRefund& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREFUND_H
