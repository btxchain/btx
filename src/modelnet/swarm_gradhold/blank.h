// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_BLANK_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts an update id that can be recorded.
 * An empty id is UPDATE. The caller stores nothing on that result.
 */
class SwarmGradHoldBlank {
public:
    bool accept(const std::string& update_id, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_BLANK_H
