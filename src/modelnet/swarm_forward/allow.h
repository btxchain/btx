// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_ALLOW_H
#define BITCOIN_MODELNET_SWARM_FORWARD_ALLOW_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Commitment, liquidity, and expiry gate.
 * Calls SwarmForwardAllowed with a margin of 160. On refusal the helper
 * error is kept when it sets one; otherwise the result is MARGIN.
 * Refusal stores nothing.
 */
class SwarmForwardAllow {
public:
    bool Accept(bool incoming_committed, int64_t liquidity, int64_t amount, int incoming_expiry, int height,
                std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_ALLOW_H
