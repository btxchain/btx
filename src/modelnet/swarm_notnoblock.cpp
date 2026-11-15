// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoblock.h>

#include <string>

namespace modelnet {

SwarmNotNoBlockResult SwarmNoteNotNoBlock(const SwarmNotNoBlock& note, std::string& err)
{
    SwarmNotNoBlockResult result;
    result.published = false;
    result.admitted = false;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.published = false;
        result.admitted = false;
        err = "RUN";
        return result;
    }
    // A safety failure or a broad regression is not published.
    if (note.safety_fail || note.broad_regression) {
        result.code = "BLOCK";
        result.published = false;
        result.admitted = false;
        err = "BLOCK";
        return result;
    }
    if (note.want_publish) {
        result.code = "BLOCK";
        result.published = false;
        result.admitted = false;
        err = "BLOCK";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
