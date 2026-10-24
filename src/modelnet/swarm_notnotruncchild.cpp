// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotruncchild.h>

#include <string>

namespace modelnet {

SwarmNotNoTruncChildResult SwarmNoteNotNoTruncChild(const SwarmNotNoTruncChild& note, std::string& err)
{
    SwarmNotNoTruncChildResult result;
    result.streamed = false;
    result.activated = false;
    // A truncated child streams nothing and does not activate.
    if (note.child_id.empty()) {
        result.code = "CHILD";
        result.streamed = false;
        result.activated = false;
        err = "CHILD";
        return result;
    }
    if (note.truncated) {
        result.code = "NOT_STREAMED";
        result.streamed = false;
        result.activated = false;
        err = "NOT_STREAMED";
        return result;
    }
    if (note.want_stream) {
        result.code = "HELD";
        result.streamed = false;
        result.activated = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.streamed = false;
    result.activated = false;
    err.clear();
    return result;
}

} // namespace modelnet
