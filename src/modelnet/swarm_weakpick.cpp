// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_weakpick.h>

namespace modelnet {

SwarmWeakPickResult SwarmPickWeakness(const SwarmWeakPick& pick, std::string& err)
{
    // A proposer can name a weakness and a remaining slot. It does not run the experiment.
    SwarmWeakPickResult result;
    result.running = false;
    result.scheduled = false;
    result.slots_left = 0;

    if (pick.proposer_id.empty()) {
        result.code = "PROPOSER";
        err = "PROPOSER";
        result.scheduled = false;
        result.running = false;
        result.slots_left = 0;
        return result;
    }
    if (pick.weakness_id.empty()) {
        result.code = "WEAKNESS";
        err = "WEAKNESS";
        result.scheduled = false;
        result.running = false;
        result.slots_left = 0;
        return result;
    }
    if (pick.budget_slots < 0 || pick.used_slots < 0 || pick.used_slots > pick.budget_slots) {
        result.code = "BUDGET";
        err = "BUDGET";
        result.scheduled = false;
        result.running = false;
        result.slots_left = 0;
        return result;
    }
    if (pick.used_slots == pick.budget_slots) {
        result.code = "FULL";
        err = "FULL";
        result.scheduled = false;
        result.running = false;
        result.slots_left = 0;
        return result;
    }
    if (pick.want_schedule) {
        result.code = "HELD";
        err = "HELD";
        result.scheduled = true;
        result.running = false;
        result.slots_left = pick.budget_slots - pick.used_slots - 1;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.scheduled = false;
    result.running = false;
    result.slots_left = pick.budget_slots - pick.used_slots;
    return result;
}

} // namespace modelnet
