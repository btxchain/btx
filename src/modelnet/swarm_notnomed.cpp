// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomed.h>

#include <string>

namespace modelnet {

SwarmNotNoMedResult SwarmNoteNotNoMed(const SwarmNotNoMed& note, std::string& err)
{
    SwarmNotNoMedResult result;
    result.promoted = false;
    result.admitted = false;
    if (note.context_id.empty()) {
        result.code = "CONTEXT";
        result.promoted = false;
        result.admitted = false;
        err = "CONTEXT";
        return result;
    }
    // A context length is not a realm promotion.
    if (note.tokens != 0) {
        result.code = "NOT_PROMOTED";
        result.promoted = false;
        result.admitted = false;
        err = "NOT_PROMOTED";
        return result;
    }
    if (note.want_promote) {
        result.code = "NOT_PROMOTED";
        result.promoted = false;
        result.admitted = false;
        err = "NOT_PROMOTED";
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
