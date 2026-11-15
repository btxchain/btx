// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocohortexp2.h>

namespace modelnet {

SwarmNotNoCohortExp2Result SwarmNoteNotNoCohortExp2(const SwarmNotNoCohortExp2& note, std::string& err)
{
    // Cohort expiry stays inclusive.
    SwarmNotNoCohortExp2Result result;
    result.excluded = false;
    if (note.cohort_id.empty()) {
        result.code = "COHORT";
        result.excluded = false;
        err = "COHORT";
        return result;
    }
    if (note.want_exclude) {
        result.code = "HELD";
        result.excluded = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.excluded = false;
    err.clear();
    return result;
}

} // namespace modelnet
