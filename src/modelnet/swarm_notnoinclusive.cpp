// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinclusive.h>

#include <string>

namespace modelnet {

SwarmNotNoInclusiveResult SwarmNoteNotNoInclusive(const SwarmNotNoInclusive& note, std::string& err)
{
    SwarmNotNoInclusiveResult result;
    result.kept = false;
    result.trained = false;
    if (note.cohort_id.empty()) {
        result.code = "COHORT";
        result.kept = false;
        result.trained = false;
        err = "COHORT";
        return result;
    }
    // Inclusive expiry: now greater than or equal to until keeps nothing.
    if (note.expired) {
        result.code = "EXPIRED";
        result.kept = false;
        result.trained = false;
        err = "EXPIRED";
        return result;
    }
    if (note.want_keep) {
        result.code = "HELD";
        result.kept = false;
        result.trained = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.kept = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
