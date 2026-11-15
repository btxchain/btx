// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnat.h>

#include <string>

namespace modelnet {

SwarmNotNatResult SwarmNoteNotNat(const SwarmNotNat& note, std::string& err)
{
    SwarmNotNatResult result;
    result.traversed = false;
    // Family discovery does not traverse NAT.
    if (note.peer_id.empty()) {
        result.code = "PEER";
        result.traversed = false;
        err = "PEER";
        return result;
    }
    if (note.want_traverse) {
        result.code = "NO_NAT";
        result.traversed = false;
        err = "NO_NAT";
        return result;
    }
    result.code = "NOTED";
    result.traversed = false;
    err.clear();
    return result;
}

} // namespace modelnet
