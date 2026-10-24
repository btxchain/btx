// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_HEIGHT_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_HEIGHT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Accepts a refund height that can be stored.
 * refund_height below 1 is HEIGHT. The caller stores nothing on that result.
 */
class SwarmAdminHoldHeight {
public:
    bool accept(int64_t refund_height, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_HEIGHT_H
