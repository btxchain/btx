// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISPUTESTAY_NAME_H
#define BITCOIN_MODELNET_SWARM_DISPUTESTAY_NAME_H

#include <string>

namespace modelnet {

/**
 * Copies a dispute id as the recorded name.
 * The characters are kept as written. No atoms are copied.
 * An empty id copies nothing.
 */
class SwarmDisputeStayName {
public:
    std::string copy(const std::string& dispute) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISPUTESTAY_NAME_H
