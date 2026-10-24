// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobase.h>

namespace modelnet {

SwarmNotNoBaseResult SwarmNoteNotNoBase(const SwarmNotNoBase& note, std::string& err)
{
    SwarmNotNoBaseResult result;
    result.published = false;
    result.multiplier = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.multiplier = 0;
        err = "RUN";
        return result;
    }
    // A baseline note publishes no multiplier.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.multiplier = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.multiplier = 0;
    err.clear();
    return result;
}

} // namespace modelnet
