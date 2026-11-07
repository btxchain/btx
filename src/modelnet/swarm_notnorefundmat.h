// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREFUNDMAT_H
#define BTX_MODELNET_SWARM_NOTNOREFUNDMAT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one channel. mature says the channel has matured.
 * want_refund asks this note to refund.
 *
 * An immature refund pays nothing.
 * refunded stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoRefundMat {
    std::string channel_id;
    bool mature{false};
    bool want_refund{false};
};

/**
 * Outcome of noting a channel. refunded stays false and atoms stays 0 on
 * every path: an immature refund pays nothing.
 */
struct SwarmNotNoRefundMatResult {
    std::string code;
    bool refunded{false};
    int64_t atoms{0};
};

/**
 * Note a channel without refunding it.
 * Order, first match wins: an empty channel_id is CHANNEL.
 * mature false is NOT_MATURE even when want_refund is false.
 * want_refund is HELD. Otherwise the note is NOTED and err is cleared.
 * refunded stays false and atoms stays 0 on every path. An immature
 * refund pays nothing.
 */
SwarmNotNoRefundMatResult SwarmNoteNotNoRefundMat(const SwarmNotNoRefundMat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREFUNDMAT_H
