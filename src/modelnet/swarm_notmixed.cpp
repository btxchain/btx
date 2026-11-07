// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmixed.h>

#include <string>

namespace modelnet {

SwarmNotMixedResult SwarmNoteNotMixed(const SwarmNotMixed& note, std::string& err)
{
    SwarmNotMixedResult result;
    result.mixed = false;
    // Mixed precision has not run.
    if (note.job_id.empty()) {
        result.code = "JOB";
        result.mixed = false;
        err = "JOB";
        return result;
    }
    if (note.want_mixed) {
        result.code = "NOT_MIXED";
        result.mixed = false;
        err = "NOT_MIXED";
        return result;
    }
    result.code = "NOTED";
    result.mixed = false;
    err.clear();
    return result;
}

} // namespace modelnet
