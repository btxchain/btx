// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBLOCKSPACE2_H
#define BTX_MODELNET_SWARM_NOTNOBLOCKSPACE2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about block spacing. chain_id names the chain.
 * want_guarantee asks this note to treat the spacing as a wall-clock
 * guarantee.
 *
 * Block spacing stays 90 seconds and is not a wall-clock guarantee.
 */
struct SwarmNotNoBlockSpace2 {
    std::string chain_id;
    bool want_guarantee{false};
};

/**
 * Outcome of noting block spacing. guaranteed stays false and seconds
 * stays 90 on every path.
 *
 * Block spacing stays 90 seconds and is not a wall-clock guarantee.
 */
struct SwarmNotNoBlockSpace2Result {
    std::string code;
    bool guaranteed{false};
    int64_t seconds{90};
};

/**
 * Note block spacing without treating it as a wall-clock guarantee.
 * Order, first match wins: an empty chain_id is CHAIN. want_guarantee
 * is HELD. Otherwise the note is NOTED and err is cleared. guaranteed
 * stays false and seconds stays 90 on every path.
 *
 * Block spacing stays 90 seconds and is not a wall-clock guarantee.
 */
SwarmNotNoBlockSpace2Result SwarmNoteNotNoBlockSpace2(const SwarmNotNoBlockSpace2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBLOCKSPACE2_H
