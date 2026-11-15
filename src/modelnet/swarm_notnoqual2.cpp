// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoqual2.h>

namespace modelnet {

SwarmNotNoQual2Result SwarmNoteNotNoQual2(const SwarmNotNoQual2& note, std::string& err)
{
    SwarmNotNoQual2Result result;
    result.promoted = false;
    result.admitted = false;
    if (note.realm_id.empty()) {
        result.code = "REALM";
        result.promoted = false;
        result.admitted = false;
        err = "REALM";
        return result;
    }
    // A quality graduation is not a realm promotion.
    if (note.graduated) {
        result.code = "NOT_PROMOTED";
        result.promoted = false;
        result.admitted = false;
        err = "NOT_PROMOTED";
        return result;
    }
    if (note.want_promote) {
        result.code = "HELD";
        result.promoted = false;
        result.admitted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
