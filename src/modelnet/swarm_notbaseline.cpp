// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notbaseline.h>

namespace modelnet {

SwarmNotBaselineResult SwarmNoteNotBaseline(const SwarmNotBaseline& note, std::string& err)
{
    SwarmNotBaselineResult result;
    result.published = false;
    result.tokens_per_sec = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.tokens_per_sec = 0;
        err = "RUN";
        return result;
    }
    // A four-token generation is not a baseline.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.tokens_per_sec = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.tokens_per_sec = 0;
    err.clear();
    return result;
}

} // namespace modelnet
