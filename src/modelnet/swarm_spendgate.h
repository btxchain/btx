// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SPENDGATE_H
#define BTX_MODELNET_SWARM_SPENDGATE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A scheduler spend request. A scheduler must not hold a spend key.
 * Nothing is signed and nothing is broadcast.
 */
struct SwarmSpendRequest {
    std::string scheduler_id;
    int64_t atoms{0};
    bool spend_key_present{false};
};

/**
 * Outcome of refusing a scheduler spend. signed_spend stays false:
 * nothing is signed and nothing is broadcast.
 */
struct SwarmSpendResult {
    bool signed_spend{false};
    std::string code;
};

/**
 * Refuse a scheduler spend. Order, first match wins: an empty
 * scheduler_id or atoms <= 0 is SPEND. A present spend key is
 * KEY_REFUSED. A scheduler must not hold a spend key. Otherwise the
 * result is REFUSED and err is cleared. signed_spend stays false on
 * every path. Nothing is signed and nothing is broadcast.
 */
SwarmSpendResult SwarmRefuseSchedulerSpend(const SwarmSpendRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SPENDGATE_H
