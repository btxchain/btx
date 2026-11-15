// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SPACINGKEEP_H
#define BTX_MODELNET_SWARM_SPACINGKEEP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a chain keeps its block spacing.
 * The target stays 90 seconds and is not a wall-clock guarantee.
 */
struct SwarmSpacingKeep {
    std::string chain_id;
    bool want_guarantee{false};
};

/**
 * Outcome of keeping block spacing. guaranteed stays false and seconds
 * stays 90 on every path.
 */
struct SwarmSpacingKeepResult {
    std::string code;
    bool guaranteed{false};
    int64_t seconds{90};
};

/**
 * Keep the block spacing. Empty chain_id is CHAIN. A guarantee request
 * is HELD. Otherwise the note is NOTED and err is clear. guaranteed stays
 * false and seconds stays 90 on every path.
 */
SwarmSpacingKeepResult SwarmKeepBlockSpacing(const SwarmSpacingKeep& chain, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SPACINGKEEP_H
