// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquorum.h>

#include <string>

namespace modelnet {

SwarmNotNoQuorumResult SwarmNoteNotNoQuorum(const SwarmNotNoQuorum& note, std::string& err)
{
    SwarmNotNoQuorumResult result;
    result.settled = false;
    result.bytes_moved = false;
    // Evaluators in one trust domain do not settle.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.settled = false;
        result.bytes_moved = false;
        err = "REPORT";
        return result;
    }
    if (note.same_domain) {
        result.code = "SAME_DOMAIN";
        result.settled = false;
        result.bytes_moved = false;
        err = "SAME_DOMAIN";
        return result;
    }
    if (note.want_settle) {
        result.code = "HELD";
        result.settled = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
