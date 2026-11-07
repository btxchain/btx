// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocohort2.h>

namespace modelnet {

SwarmNotNoCohort2Result SwarmNoteNotNoCohort2(const SwarmNotNoCohort2& note, std::string& err)
{
    // Cohort expiry is inclusive. This note drops no member.
    SwarmNotNoCohort2Result result;
    result.dropped = false;
    if (note.cohort_id.empty()) {
        result.code = "COHORT";
        result.dropped = false;
        err = "COHORT";
        return result;
    }
    if (note.inclusive) {
        result.code = "STAYS";
        result.dropped = false;
        err = "STAYS";
        return result;
    }
    if (note.want_drop) {
        result.code = "HELD";
        result.dropped = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.dropped = false;
    err.clear();
    return result;
}

} // namespace modelnet
