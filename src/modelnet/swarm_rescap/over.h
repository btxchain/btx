// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_OVER_H
#define BITCOIN_MODELNET_SWARM_RESCAP_OVER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * threads above 64 is CAPPED. The caller stores nothing.
 * A count of 64 or below is not this refusal.
 */
class SwarmResCapOver {
public:
    bool accept(int64_t threads, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_OVER_H
