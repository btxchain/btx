// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoablate2.h>

#include <string>

namespace modelnet {

SwarmNotNoAblate2Result SwarmNoteNotNoAblate2(const SwarmNotNoAblate2& note, std::string& err)
{
    SwarmNotNoAblate2Result result;
    result.published = false;
    result.rows = 0;
    // A unit note publishes no ablation.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.rows = 0;
        err = "RUN";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.rows = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.rows = 0;
    err.clear();
    return result;
}

} // namespace modelnet
