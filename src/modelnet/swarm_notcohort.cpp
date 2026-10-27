// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcohort.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotCohortResult SwarmNoteNotCohort(const SwarmNotCohort& note, std::string& err)
{
    SwarmNotCohortResult result;
    result.extended = false;
    result.expired = false;
    if (note.cohort_id.empty()) {
        result.code = "COHORT";
        result.extended = false;
        result.expired = false;
        err = "COHORT";
        return result;
    }
    if (note.want_extend) {
        result.code = "HELD";
        result.extended = false;
        result.expired = false;
        err = "HELD";
        return result;
    }
    // Equality is expiry. This note does not extend a cohort.
    if (note.now_ms >= note.until_ms) {
        result.code = "EXPIRED";
        result.extended = false;
        result.expired = true;
        err = "EXPIRED";
        return result;
    }
    result.code = "NOTED";
    result.extended = false;
    result.expired = false;
    err.clear();
    return result;
}

} // namespace modelnet
