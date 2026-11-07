// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REFUNDHOLD_H
#define BTX_MODELNET_SWARM_REFUNDHOLD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One refund-height check. Reaching refund_height does not broadcast and
 * does not create a transaction.
 */
struct SwarmRefundHoldRequest {
    int64_t height{0};
    int64_t refund_height{0};
    bool disrupted{false};
    bool want_broadcast{false};
};

/**
 * Hold answer. broadcast stays false. There is no transaction id.
 */
struct SwarmRefundHoldResult {
    bool mature{false};
    bool broadcast{false};
    std::string code;
};

/**
 * Decides whether a refund height is held. broadcast stays false.
 * Reaching refund_height does not broadcast and does not create a transaction.
 *
 * Order: height < 0 or refund_height < 1 is REFUND. want_broadcast is
 * BROADCAST_FORBIDDEN, even when height >= refund_height and disrupted is
 * true. height < refund_height is EARLY. disrupted is DISRUPTED, mature is
 * true, and err is cleared. Otherwise the result is MATURE, mature is true,
 * and err is cleared.
 */
SwarmRefundHoldResult SwarmHoldRefund(const SwarmRefundHoldRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REFUNDHOLD_H
