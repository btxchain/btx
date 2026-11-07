// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_EXPLORE_H
#define BTX_MODELNET_SWARM_EXPLORE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one exploration split. pool_id names the pool.
 * slots is the slot count. exploration_ppm is parts per million, from
 * 0 through 1000000. candidate_count is the number of candidates.
 * want_assign asks this note to assign slots.
 *
 * The known illustration is slots 5, exploration_ppm 200000, and
 * candidate_count 3, which records first 1, second 2, third 2.
 * This note does not invent a general allocator. Nothing is scheduled.
 * assigned stays false on every path. No hostnames or IPs are used.
 */
struct SwarmExplore {
    std::string pool_id;
    int64_t slots{0};
    int64_t exploration_ppm{0};
    int64_t candidate_count{0};
    bool want_assign{false};
};

/**
 * Outcome of noting an exploration split. assigned stays false: this
 * note does not schedule an assignment. first, second, and third are
 * the recorded illustration counts, or zero when the input is refused.
 */
struct SwarmExploreResult {
    int64_t first{0};
    int64_t second{0};
    int64_t third{0};
    bool assigned{false};
    std::string code;
};

/**
 * Note an exploration split without assigning it.
 * Order, first match wins:
 * an empty pool_id, slots below 1, exploration_ppm below 0,
 * exploration_ppm above 1000000, or candidate_count below 1 is EXPLORE.
 * first, second, and third are 0 and err is EXPLORE.
 * An input that is not exactly slots 5, exploration_ppm 200000, and
 * candidate_count 3 is ILLUSTRATION. The counts stay 0 and err is
 * ILLUSTRATION. This wins even when want_assign is true. This note
 * does not invent a general allocator.
 * want_assign is HELD. first is 1, second is 2, third is 2, and err is
 * cleared. This note does not schedule an assignment.
 * Otherwise the note is NOTED with the same counts and err is cleared.
 * assigned stays false. Nothing is scheduled.
 */
SwarmExploreResult SwarmNoteExplore(const SwarmExplore& explore, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_EXPLORE_H
