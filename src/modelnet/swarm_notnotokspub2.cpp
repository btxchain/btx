// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotokspub2.h>

#include <string>

namespace modelnet {

SwarmNotNoToksPub2Result SwarmNoteNotNoToksPub2(const SwarmNotNoToksPub2& note, std::string& err)
{
    SwarmNotNoToksPub2Result result;
    result.published = false;
    // This note publishes no tokens per second.
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        err = "SAMPLE";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
