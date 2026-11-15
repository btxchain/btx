// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/announce.h>

#include <modelnet/swarm_dedup/codes.h>
#include <modelnet/swarm_dedup/gate.h>
#include <modelnet/swarm_dedup/index.h>

#include <string>

namespace modelnet {

bool SwarmPieceDedupAnnounce(SwarmPieceDedupIndex& index, const std::string& peer, const std::string& piece_id, bool is_private, std::string& err)
{
    if (!SwarmPieceDedupAllowAnnounce(peer, piece_id, is_private, err)) {
        return false;
    }
    if (index.Contains(peer, piece_id)) {
        err = kSwarmPieceDedupReplay;
        return false;
    }
    if (!index.Insert(peer, piece_id)) {
        err = kSwarmPieceDedupReplay;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
