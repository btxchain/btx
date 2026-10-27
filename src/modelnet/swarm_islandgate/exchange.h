// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ISLANDGATE_EXCHANGE_H
#define BITCOIN_MODELNET_SWARM_ISLANDGATE_EXCHANGE_H

#include <string>

namespace modelnet {

/**
 * An exchange moves no bytes.
 * Exchange sets err to HELD and returns false. exchanged() stays false.
 * There is no method that sets exchanged or moves bytes.
 */
class SwarmIslandGateExchange {
public:
    bool Exchange(std::string& err);
    bool exchanged() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ISLANDGATE_EXCHANGE_H
