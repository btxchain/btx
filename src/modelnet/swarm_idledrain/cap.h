// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_CAP_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_CAP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Admit cap.
 * A count below 64 may take one more worker. A count of 64, or any
 * count whose next step would pass 64, is CAPPED. This does not
 * change the count.
 */
class SwarmIdleDrainCap {
public:
    bool accept(int64_t workers, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_CAP_H
