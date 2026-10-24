// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_UNDER_H
#define BITCOIN_MODELNET_SWARM_RESCAP_UNDER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * threads below 1 is CAP. The caller stores nothing.
 * A count of 1 or more is not this refusal.
 */
class SwarmResCapUnder {
public:
    bool accept(int64_t threads, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_UNDER_H
