// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_ID_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_ID_H

#include <string>

namespace modelnet {

/**
 * Accepts a candidate id that can be staged.
 * An empty id is ID. The caller stores nothing on that result.
 */
class SwarmCanaryBackIdGate {
public:
    bool accept(const std::string& id, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_ID_H
