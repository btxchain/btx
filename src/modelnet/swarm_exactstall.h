// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_EXACTSTALL_H
#define BTX_MODELNET_SWARM_EXACTSTALL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one chain. want_mine asks this note to mine.
 *
 * A mine request past the ExactReplay stall is held and mines nothing.
 * mined stays false and blocks stays 0 on every path.
 */
struct SwarmExactStall {
    std::string chain_id;
    bool want_mine{false};
};

/**
 * Outcome of holding a mine request. mined stays false and blocks stays 0
 * on every path: a mine request past the ExactReplay stall is held and
 * mines nothing.
 */
struct SwarmExactStallResult {
    std::string code;
    bool mined{false};
    int64_t blocks{0};
};

/**
 * Hold a mine request past the ExactReplay stall.
 * Order, first match wins: an empty chain_id is CHAIN. want_mine is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * mined stays false and blocks stays 0 on every path.
 * A mine request past the ExactReplay stall is held and mines nothing.
 */
SwarmExactStallResult SwarmHoldExactMine(const SwarmExactStall& chain, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_EXACTSTALL_H
