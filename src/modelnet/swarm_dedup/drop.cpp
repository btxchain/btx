// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/drop.h>

#include <modelnet/swarm_dedup/codes.h>
#include <modelnet/swarm_dedup/index.h>

#include <string>

namespace modelnet {

bool SwarmPieceDedupDrop(SwarmPieceDedupIndex& index, const std::string& peer, const std::string& piece_id, std::string& err)
{
    if (!index.Erase(peer, piece_id)) {
        err = kSwarmPieceDedupMissing;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
