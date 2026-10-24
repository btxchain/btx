// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_NAME_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_NAME_H

#include <string>

namespace modelnet {

/**
 * Copies an update id as the recorded name.
 * The characters are kept as written. No gradient bytes are copied.
 * An empty id copies nothing.
 */
class SwarmGradHoldName {
public:
    std::string copy(const std::string& update_id) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_NAME_H
