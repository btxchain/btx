// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocohort.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoCohortResult SwarmNoteNotNoCohort(const SwarmNotNoCohort& note, std::string& err)
{
    SwarmNotNoCohortResult result;
    result.spent = false;
    result.atoms = 0;
    if (note.cohort_id.empty()) {
        result.code = "COHORT";
        result.spent = false;
        result.atoms = 0;
        err = "COHORT";
        return result;
    }
    // Equality is expiry. An inclusive cohort expiry spends nothing.
    if (note.now_ms >= note.until_ms) {
        result.code = "EXPIRED";
        result.spent = false;
        result.atoms = 0;
        err = "EXPIRED";
        return result;
    }
    if (note.want_spend) {
        result.code = "HELD";
        result.spent = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
