// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonataddr2.h>

#include <string>

namespace modelnet {

SwarmNotNoNatAddr2Result SwarmNoteNotNoNatAddr2(const SwarmNotNoNatAddr2& note, std::string& err)
{
    SwarmNotNoNatAddr2Result result;
    result.published = false;
    // NAT traversal publishes no address.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.published = false;
        err = "PEER";
        return result;
    }
    if (note.nat) {
        result.code = "NOT_PUBLISHED";
        result.published = false;
        err = "NOT_PUBLISHED";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
