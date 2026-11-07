// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodomain2.h>

#include <string>

namespace modelnet {

SwarmNotNoDomain2Result SwarmNoteNotNoDomain2(const SwarmNotNoDomain2& note, std::string& err)
{
    SwarmNotNoDomain2Result result;
    result.settled = false;
    result.bytes_moved = false;
    // A quorum needs distinct evaluators and distinct trust domains.
    // This note settles nothing.
    if (note.quorum_id.empty()) {
        result.code = "QUORUM";
        result.settled = false;
        result.bytes_moved = false;
        err = "QUORUM";
        return result;
    }
    if (!note.distinct_evaluators || !note.distinct_domains) {
        result.code = "HELD";
        result.settled = false;
        result.bytes_moved = false;
        err = "HELD";
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
