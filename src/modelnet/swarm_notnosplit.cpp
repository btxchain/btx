// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosplit.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoSplitResult SwarmNoteNotNoSplit(const SwarmNotNoSplit& note, std::string& err)
{
    SwarmNotNoSplitResult result;
    result.settled = false;
    result.atoms = 0;
    // A disagreement is not a settlement.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.settled = false;
        result.atoms = 0;
        err = "REPORT";
        return result;
    }
    if (note.disagree) {
        result.code = "SPLIT";
        result.settled = false;
        result.atoms = 0;
        err = "SPLIT";
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
