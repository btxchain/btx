// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_DROP_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_DROP_H

#include <modelnet/swarm_piecepipe/manifest.h>
#include <modelnet/swarm_piecepipe/store.h>

#include <string>

namespace modelnet {

/**
 * Erase a stored piece that no manifest lists.
 * An unknown id is PIECE. A slice that a manifest still requires is MANIFEST
 * and is left in the store.
 */
bool SwarmPiecePipeDrop(SwarmPiecePipeStore& store, const SwarmPiecePipeManifestBook& manifests, const std::string& id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_DROP_H
