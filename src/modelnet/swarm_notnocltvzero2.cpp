// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocltvzero2.h>

#include <string>

namespace modelnet {

SwarmNotNoCltvZero2Result SwarmNoteNotNoCltvZero2(const SwarmNotNoCltvZero2& note, std::string& err)
{
    SwarmNotNoCltvZero2Result result;
    result.added = false;
    result.delay = 0;
    // The sender's first edge adds no CLTV.
    if (note.edge_id.empty()) {
        result.code = "EDGE";
        result.added = false;
        result.delay = 0;
        err = "EDGE";
        return result;
    }
    if (note.first_edge) {
        result.code = "NOT_ADDED";
        result.added = false;
        result.delay = 0;
        err = "NOT_ADDED";
        return result;
    }
    if (note.want_add) {
        result.code = "HELD";
        result.added = false;
        result.delay = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    result.delay = 0;
    err.clear();
    return result;
}

} // namespace modelnet
