// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MINEHOLD_STAY_H
#define BITCOIN_MODELNET_SWARM_MINEHOLD_STAY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * The stored request stays unmined.
 * refusal() is HELD. mined() stays false. blocks() stays 0.
 * This type does not store a name and does not move bytes.
 */
class SwarmMineHoldStay {
public:
    std::string refusal() const;
    bool mined() const;
    int64_t blocks() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MINEHOLD_STAY_H
