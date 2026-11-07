// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofamily.h>

#include <string>

namespace modelnet {

SwarmNotNoFamilyResult SwarmNoteNotNoFamily(const SwarmNotNoFamily& note, std::string& err)
{
    SwarmNotNoFamilyResult result;
    result.shared = false;
    result.bytes_moved = false;
    // Family membership is not compatibility.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.shared = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (note.same_family && !note.compatible) {
        result.code = "FAMILY_NOT_COMPAT";
        result.shared = false;
        result.bytes_moved = false;
        err = "FAMILY_NOT_COMPAT";
        return result;
    }
    if (!note.same_family) {
        result.code = "SEPARATE";
        result.shared = false;
        result.bytes_moved = false;
        err = "SEPARATE";
        return result;
    }
    if (note.want_share) {
        result.code = "NOT_SHARED";
        result.shared = false;
        result.bytes_moved = false;
        err = "NOT_SHARED";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
