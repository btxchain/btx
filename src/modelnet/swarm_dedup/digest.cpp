// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/digest.h>

#include <modelnet/swarm_dedup/binding.h>
#include <modelnet/swarm_dedup/codes.h>
#include <modelnet/swarm_dedup/gate.h>

#include <string>

namespace modelnet {

bool SwarmPieceDedupDigest(SwarmPieceDedupBindings& bindings, const std::string& piece_id, const std::string& digest_hex, std::string& err)
{
    if (!SwarmPieceDedupAllowDigest(piece_id, digest_hex, err)) {
        return false;
    }
    if (bindings.Bound(piece_id)) {
        err = kSwarmPieceDedupReplay;
        return false;
    }
    if (!bindings.Put(piece_id, digest_hex)) {
        err = kSwarmPieceDedupConflict;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
