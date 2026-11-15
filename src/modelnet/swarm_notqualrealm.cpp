// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notqualrealm.h>

namespace modelnet {

SwarmNotQualRealmResult SwarmNoteNotQualRealm(const SwarmNotQualRealm& note, std::string& err)
{
    SwarmNotQualRealmResult result;
    result.realm_promoted = false;
    result.admitted = false;
    if (note.eval_id.empty()) {
        result.code = "EVAL";
        result.realm_promoted = false;
        result.admitted = false;
        err = "EVAL";
        return result;
    }
    // A quality pass is not realm promotion and not ExactReplay admission.
    if (note.quality_pass) {
        result.code = "NOT_REALM";
        result.realm_promoted = false;
        result.admitted = false;
        err = "NOT_REALM";
        return result;
    }
    if (note.want_promote) {
        result.code = "NOT_REALM";
        result.realm_promoted = false;
        result.admitted = false;
        err = "NOT_REALM";
        return result;
    }
    result.code = "NOTED";
    result.realm_promoted = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
