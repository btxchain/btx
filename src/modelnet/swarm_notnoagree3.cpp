// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoagree3.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoAgree3Result SwarmNoteNotNoAgree3(const SwarmNotNoAgree3& note, std::string& err)
{
    SwarmNotNoAgree3Result result;
    result.settled = false;
    result.atoms = 0;
    // An agreement is not a settlement.
    if (note.agreement_id.empty()) {
        result.code = "AGREEMENT";
        result.settled = false;
        result.atoms = 0;
        err = "AGREEMENT";
        return result;
    }
    if (note.agreement) {
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
