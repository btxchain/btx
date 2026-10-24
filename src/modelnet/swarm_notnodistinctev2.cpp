// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodistinctev2.h>

#include <string>

namespace modelnet {

SwarmNotNoDistinctEv2Result SwarmNoteNotNoDistinctEv2(const SwarmNotNoDistinctEv2& note, std::string& err)
{
    SwarmNotNoDistinctEv2Result result;
    result.counted = false;
    // The same evaluator is not a quorum.
    if (note.quorum_id.empty()) {
        result.code = "QUORUM";
        result.counted = false;
        err = "QUORUM";
        return result;
    }
    if (note.same_evaluator) {
        result.code = "NOT_QUORUM";
        result.counted = false;
        err = "NOT_QUORUM";
        return result;
    }
    if (note.want_count) {
        result.code = "HELD";
        result.counted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.counted = false;
    err.clear();
    return result;
}

} // namespace modelnet
