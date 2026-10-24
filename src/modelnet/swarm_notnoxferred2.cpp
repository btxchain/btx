// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoxferred2.h>

#include <string>

namespace modelnet {

SwarmNotNoXferred2Result SwarmNoteNotNoXferred2(const SwarmNotNoXferred2& note, std::string& err)
{
    SwarmNotNoXferred2Result result;
    result.published = false;
    result.bytes = 0;
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        result.bytes = 0;
        err = "SAMPLE";
        return result;
    }
    // A unit note publishes no transferred-byte count.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.bytes = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
