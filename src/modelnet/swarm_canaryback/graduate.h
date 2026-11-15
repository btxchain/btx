// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CANARYBACK_GRADUATE_H
#define BITCOIN_MODELNET_SWARM_CANARYBACK_GRADUATE_H

#include <string>

namespace modelnet {

/**
 * Refuses graduation.
 * The result is always REALM. There is no active id here to change
 * and no flag that can become graduated.
 */
class SwarmCanaryBackGraduate {
public:
    bool Apply(std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CANARYBACK_GRADUATE_H
