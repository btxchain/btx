// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofamily2.h>

#include <string>

namespace modelnet {

SwarmNotNoFamily2Result SwarmNoteNotNoFamily2(const SwarmNotNoFamily2& note, std::string& err)
{
    SwarmNotNoFamily2Result result;
    result.published = false;
    result.bytes_moved = false;
    // A private family is not published.
    if (note.family_id.empty()) {
        result.code = "FAMILY";
        result.published = false;
        result.bytes_moved = false;
        err = "FAMILY";
        return result;
    }
    if (note.private_family) {
        result.code = "NOT_PUBLISHED";
        result.published = false;
        result.bytes_moved = false;
        err = "NOT_PUBLISHED";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
