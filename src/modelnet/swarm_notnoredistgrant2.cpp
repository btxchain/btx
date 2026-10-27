// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoredistgrant2.h>

#include <string>

namespace modelnet {

SwarmNotNoRedistGrant2Result SwarmNoteNotNoRedistGrant2(const SwarmNotNoRedistGrant2& note, std::string& err)
{
    SwarmNotNoRedistGrant2Result result;
    result.shared = false;
    // A download license is not a redistribution grant.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.shared = false;
        err = "LICENSE";
        return result;
    }
    if (note.download) {
        result.code = "NOT_SHARED";
        result.shared = false;
        err = "NOT_SHARED";
        return result;
    }
    if (note.want_share) {
        result.code = "HELD";
        result.shared = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    err.clear();
    return result;
}

} // namespace modelnet
