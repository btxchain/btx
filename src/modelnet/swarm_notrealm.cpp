// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrealm.h>

namespace modelnet {

SwarmNotRealmResult SwarmNoteNotRealm(const SwarmNotRealm& note, std::string& err)
{
    SwarmNotRealmResult result;
    result.promoted = false;
    if (note.candidate_id.empty()) {
        result.code = "REALM";
        result.promoted = false;
        err = "REALM";
        return result;
    }
    // Quality graduation is not realm promotion.
    if (note.want_realm_promote) {
        result.code = "NOT_REALM";
        result.promoted = false;
        err = "NOT_REALM";
        return result;
    }
    if (note.quality_passed) {
        result.code = "HELD";
        result.promoted = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    err.clear();
    return result;
}

} // namespace modelnet
