// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorealm.h>

namespace modelnet {

SwarmNotNoRealmResult SwarmNoteNotNoRealm(const SwarmNotNoRealm& note, std::string& err)
{
    SwarmNotNoRealmResult result;
    result.promoted = false;
    result.admitted = false;
    if (note.eval_id.empty()) {
        result.code = "EVAL";
        result.promoted = false;
        result.admitted = false;
        err = "EVAL";
        return result;
    }
    // A quality pass is not a realm promotion.
    if (note.quality_pass) {
        result.code = "NOT_REALM";
        result.promoted = false;
        result.admitted = false;
        err = "NOT_REALM";
        return result;
    }
    if (note.want_promote) {
        result.code = "NOT_REALM";
        result.promoted = false;
        result.admitted = false;
        err = "NOT_REALM";
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
