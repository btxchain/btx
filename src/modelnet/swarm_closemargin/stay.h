// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSEMARGIN_STAY_H
#define BITCOIN_MODELNET_SWARM_CLOSEMARGIN_STAY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * The stored request stays unshrunk.
 * refusal() is HELD. margin_blocks() stays 160. shrunk() stays false.
 * This type does not store a count and does not move bytes.
 */
class SwarmCloseMarginHoldStay {
public:
    std::string refusal() const;
    int64_t margin_blocks() const;
    bool shrunk() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSEMARGIN_STAY_H
