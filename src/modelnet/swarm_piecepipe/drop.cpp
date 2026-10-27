// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/drop.h>

#include <modelnet/swarm_piecepipe/codes.h>

#include <string>

namespace modelnet {

bool SwarmPiecePipeDrop(SwarmPiecePipeStore& store, const SwarmPiecePipeManifestBook& manifests, const std::string& id, std::string& err)
{
    if (!store.contains(id)) {
        err = kSwarmPiecePipePiece;
        return false;
    }
    if (manifests.requires_slice(id)) {
        err = kSwarmPiecePipeManifest;
        return false;
    }
    store.erase(id);
    err.clear();
    return true;
}

} // namespace modelnet
