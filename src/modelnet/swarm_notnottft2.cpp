// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnottft2.h>

namespace modelnet {

SwarmNotNoTtft2Result SwarmNoteNotNoTtft2(const SwarmNotNoTtft2& note, std::string& err)
{
    SwarmNotNoTtft2Result result;
    result.published = false;
    result.ttft_us = 0;
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        result.ttft_us = 0;
        err = "SAMPLE";
        return result;
    }
    // A unit note publishes no time to first token.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.ttft_us = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.ttft_us = 0;
    err.clear();
    return result;
}

} // namespace modelnet
