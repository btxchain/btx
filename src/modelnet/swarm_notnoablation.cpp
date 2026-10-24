// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoablation.h>

namespace modelnet {

SwarmNotNoAblationResult SwarmNoteNotNoAblation(const SwarmNotNoAblation& note, std::string& err)
{
    SwarmNotNoAblationResult result;
    result.published = false;
    result.qualified = false;
    if (note.bench_id.empty()) {
        result.code = "BENCH";
        result.published = false;
        result.qualified = false;
        err = "BENCH";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.qualified = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.qualified = false;
    err.clear();
    return result;
}

} // namespace modelnet
