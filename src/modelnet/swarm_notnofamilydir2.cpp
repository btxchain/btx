// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofamilydir2.h>

#include <string>

namespace modelnet {

SwarmNotNoFamilyDir2Result SwarmNoteNotNoFamilyDir2(const SwarmNotNoFamilyDir2& note, std::string& err)
{
    SwarmNotNoFamilyDir2Result result;
    result.published = false;
    // A global family directory publishes no address.
    if (note.directory_id.empty()) {
        result.code = "DIRECTORY";
        result.published = false;
        err = "DIRECTORY";
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
