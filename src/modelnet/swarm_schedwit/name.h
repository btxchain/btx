// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_NAME_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_NAME_H

#include <string>

namespace modelnet {

/**
 * Copies a witness as the recorded witness.
 * The witness is an opaque short label. The characters are kept as written.
 * No payload bytes are copied. An empty witness copies nothing.
 */
class SwarmSchedWitnessName {
public:
    std::string copy(const std::string& witness) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_NAME_H
