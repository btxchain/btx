// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WEAKPICK_H
#define BTX_MODELNET_SWARM_WEAKPICK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local proposal that names one weakness and a remaining slot.
 * A proposer can name a weakness and a remaining slot. It does not
 * run the experiment.
 */
struct SwarmWeakPick {
    std::string proposer_id;
    std::string weakness_id;
    int64_t budget_slots{0};
    int64_t used_slots{0};
    bool want_schedule{false};
};

/**
 * A local weakness note. running stays false: naming a weakness does
 * not run the experiment.
 */
struct SwarmWeakPickResult {
    std::string code;
    bool scheduled{false};
    bool running{false};
    int64_t slots_left{0};
};

/**
 * Order, first match wins: an empty proposer_id is PROPOSER. An empty
 * weakness_id is WEAKNESS. A negative budget_slots, a negative
 * used_slots, or used_slots above budget_slots is BUDGET. used_slots
 * equal to budget_slots is FULL. A request that wants a schedule is
 * HELD, scheduled, and leaves budget_slots - used_slots - 1. Otherwise
 * the note is NOTED, err is clear, and slots_left is budget_slots -
 * used_slots. running stays false on every path. A proposer can name
 * a weakness and a remaining slot. It does not run the experiment.
 */
SwarmWeakPickResult SwarmPickWeakness(const SwarmWeakPick& pick, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WEAKPICK_H
