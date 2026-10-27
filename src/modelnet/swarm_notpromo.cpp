// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpromo.h>

#include <string>

namespace modelnet {

SwarmNotPromoResult SwarmNoteNotPromo(const SwarmNotPromo& note, std::string& err)
{
    SwarmNotPromoResult result;
    result.promoted = false;
    // An interrupted candidate promotion has not been shown.
    if (note.candidate_id.empty()) {
        result.code = "CANDIDATE";
        result.promoted = false;
        err = "CANDIDATE";
        return result;
    }
    if (note.want_promote) {
        result.code = "NOT_PROMOTED";
        result.promoted = false;
        err = "NOT_PROMOTED";
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    err.clear();
    return result;
}

} // namespace modelnet
