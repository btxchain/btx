// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoagree.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoAgreeResult SwarmNoteNotNoAgree(const SwarmNotNoAgree& note, std::string& err)
{
    SwarmNotNoAgreeResult result;
    result.settled = false;
    result.atoms = 0;
    // Agreement is not settlement.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.settled = false;
        result.atoms = 0;
        err = "REPORT";
        return result;
    }
    if (note.agreed) {
        result.code = "NOT_SETTLEMENT";
        result.settled = false;
        result.atoms = 0;
        err = "NOT_SETTLEMENT";
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
