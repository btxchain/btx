// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomult.h>

namespace modelnet {

SwarmNotNoMultResult SwarmNoteNotNoMult(const SwarmNotNoMult& note, std::string& err)
{
    SwarmNotNoMultResult result;
    result.published = false;
    result.multiplier = 0;
    // A short generation is not a published performance multiplier.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.multiplier = 0;
        err = "RUN";
        return result;
    }
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
