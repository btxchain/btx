// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notquorum.h>

#include <string>

namespace modelnet {

SwarmNotQuorumResult SwarmNoteNotQuorum(const SwarmNotQuorum& note, std::string& err)
{
    SwarmNotQuorumResult result;
    result.settled = false;
    // Conflicting evaluator reports are not a live quorum.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.settled = false;
        err = "REPORT";
        return result;
    }
    if (note.want_settle) {
        result.code = "NOT_QUORUM";
        result.settled = false;
        err = "NOT_QUORUM";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    err.clear();
    return result;
}

} // namespace modelnet
