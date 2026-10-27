// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotps.h>

#include <string>

namespace modelnet {

SwarmNotNoTpsResult SwarmNoteNotNoTps(const SwarmNotNoTps& note, std::string& err)
{
    SwarmNotNoTpsResult result;
    result.published = false;
    result.tokens_per_sec = 0;
    // A short generation is not a tokens-per-second measurement.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.tokens_per_sec = 0;
        err = "RUN";
        return result;
    }
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
