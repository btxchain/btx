// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_SPLIT_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_SPLIT_H

#include <modelnet/swarm_piecepipe/manifest.h>
#include <modelnet/swarm_piecepipe/store.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Split body into slices of at most 4194304 bytes and store each slice under
 * its SHA-384 hex id. The artifact id is the SHA-384 hex of the whole body,
 * not a hash of the slice ids, and is stored as the manifest root.
 * An empty body is PIECE and stores nothing. A body over 33554432 bytes is
 * PIECE_LIMIT and stores nothing. Success returns true and clears err.
 * The new manifest is not marked usable.
 */
bool SwarmPiecePipeSplit(SwarmPiecePipeStore& store, SwarmPiecePipeManifestBook& manifests, const std::vector<unsigned char>& body, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_SPLIT_H
