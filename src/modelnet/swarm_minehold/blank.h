// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MINEHOLD_BLANK_H
#define BITCOIN_MODELNET_SWARM_MINEHOLD_BLANK_H

#include <string>

namespace modelnet {

/**
 * Accepts a name that can be recorded.
 * An empty name is MINE. The caller stores nothing on that result.
 */
class SwarmMineHoldBlank {
public:
    bool accept(const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MINEHOLD_BLANK_H
