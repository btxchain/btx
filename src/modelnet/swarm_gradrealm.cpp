// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradrealm.h>

namespace modelnet {

SwarmGradRealmResult SwarmNoteGraduationRealm(const SwarmGradRealm& note, std::string& err)
{
    SwarmGradRealmResult result;
    result.realm_promoted = false;
    result.exact_replay_admitted = false;
    if (note.candidate_id.empty()) {
        result.code = "GRADUATE";
        err = "GRADUATE";
        return result;
    }
    // Realm promotion is refused even when quality passed and ExactReplay
    // was requested. Quality graduation is not realm promotion.
    if (note.want_realm_promotion) {
        result.code = "REALM_REFUSED";
        err = "REALM_REFUSED";
        return result;
    }
    // ExactReplay admission is refused even when quality passed.
    // Quality graduation is not ExactReplay admission.
    if (note.want_exact_replay) {
        result.code = "REPLAY_REFUSED";
        err = "REPLAY_REFUSED";
        return result;
    }
    if (note.quality_passed) {
        result.code = "HELD";
        result.realm_promoted = false;
        result.exact_replay_admitted = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.realm_promoted = false;
    result.exact_replay_admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
