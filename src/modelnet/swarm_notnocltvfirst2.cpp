// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocltvfirst2.h>

#include <string>

namespace modelnet {

SwarmNotNoCltvFirst2Result SwarmNoteNotNoCltvFirst2(const SwarmNotNoCltvFirst2& note, std::string& err)
{
    SwarmNotNoCltvFirst2Result result;
    result.added = false;
    // The sender first edge adds no CLTV.
    if (note.edge_id.empty()) {
        result.code = "EDGE";
        result.added = false;
        err = "EDGE";
        return result;
    }
    if (note.first_edge) {
        result.code = "NOT_ADDED";
        result.added = false;
        err = "NOT_ADDED";
        return result;
    }
    if (note.want_add) {
        result.code = "HELD";
        result.added = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.added = false;
    err.clear();
    return result;
}

} // namespace modelnet
