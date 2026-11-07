// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotokps2.h>

#include <string>

namespace modelnet {

SwarmNotNoTokps2Result SwarmNoteNotNoTokps2(const SwarmNotNoTokps2& note, std::string& err)
{
    SwarmNotNoTokps2Result result;
    result.published = false;
    result.tokens_per_sec = 0;
    // A unit note publishes no tokens per second.
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        result.tokens_per_sec = 0;
        err = "SAMPLE";
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
