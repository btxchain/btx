// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfamilydir.h>

#include <string>

namespace modelnet {

SwarmNotFamilyDirResult SwarmNoteNotFamilyDir(const SwarmNotFamilyDir& note, std::string& err)
{
    SwarmNotFamilyDirResult result;
    result.published = false;
    result.global_dir = false;
    // This note does not publish a global family directory.
    if (note.family_id.empty()) {
        result.code = "FAMILY";
        result.published = false;
        result.global_dir = false;
        err = "FAMILY";
        return result;
    }
    if (note.want_publish) {
        result.code = "NOT_PUBLISHED";
        result.published = false;
        result.global_dir = false;
        err = "NOT_PUBLISHED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.global_dir = false;
    err.clear();
    return result;
}

} // namespace modelnet
