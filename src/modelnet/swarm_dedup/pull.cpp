// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/pull.h>

#include <modelnet/swarm_dedup/codes.h>
#include <modelnet/swarm_dedup/gate.h>
#include <modelnet/swarm_dedup/index.h>

#include <string>

namespace modelnet {

bool SwarmPieceDedupPull(const SwarmPieceDedupIndex& index, const std::string& requester, const std::string& piece_id, std::string& err)
{
    if (!SwarmPieceDedupAllowPull(requester, piece_id, err)) {
        return false;
    }
    if (index.Count(piece_id) == 0) {
        err = kSwarmPieceDedupMissing;
        return false;
    }
    if (!index.OtherHolds(piece_id, requester)) {
        err = kSwarmPieceDedupAlone;
        return false;
    }
    // Another peer has announced the id. That record is not a copy.
    err = kSwarmPieceDedupHeld;
    return false;
}

} // namespace modelnet
