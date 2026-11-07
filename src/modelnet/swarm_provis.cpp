// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_provis.h>

namespace modelnet {

SwarmProvisionalResult SwarmNoteProvisional(const SwarmProvisionalNote& note, std::string& err)
{
    SwarmProvisionalResult result;
    result.published = false;
    if (note.lineage_id.empty()) {
        result.code = "LINEAGE";
        result.published = false;
        err = "LINEAGE";
        return result;
    }
    // A provisional lineage stays private. This wins even when want_public
    // is true. This note does not publish a topic and does not open a socket.
    if (note.provisional) {
        result.code = "PRIVATE";
        result.published = false;
        err = "PRIVATE";
        return result;
    }
    if (note.want_public) {
        result.code = "HELD";
        result.published = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
