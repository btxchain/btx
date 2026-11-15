// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REPLAYSTALL_H
#define BITCOIN_MODELNET_SWARM_REPLAYSTALL_H

#include <cstdint>
#include <string>

namespace modelnet {

struct SwarmReplayStall {
    int64_t tip_height{0};
    int64_t stall_height{0};
    bool want_mine{false};
};

struct SwarmReplayStallResult {
    bool mined{false};
    std::string code;
};

/**
 * Classify a replay stall.
 * Does not mine, extend a chain, or broadcast.
 */
SwarmReplayStallResult SwarmNoteReplayStall(const SwarmReplayStall& stall, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REPLAYSTALL_H
