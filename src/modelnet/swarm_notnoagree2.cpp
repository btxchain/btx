// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoagree2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoAgree2Result SwarmNoteNotNoAgree2(const SwarmNotNoAgree2& note, std::string& err)
{
    SwarmNotNoAgree2Result result;
    result.settled = false;
    result.atoms = 0;
    // Agreement is not settlement.
    if (note.quorum_id.empty()) {
        result.code = "QUORUM";
        result.settled = false;
        result.atoms = 0;
        err = "QUORUM";
        return result;
    }
    if (note.agreed) {
        result.code = "NOT_SETTLED";
        result.settled = false;
        result.atoms = 0;
        err = "NOT_SETTLED";
        return result;
    }
    if (note.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
