// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_RESUME_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_RESUME_H

#include <modelnet/swarm_piecepipe/manifest.h>
#include <modelnet/swarm_piecepipe/store.h>

#include <string>

namespace modelnet {

/**
 * Mark the artifact usable when every required slice is still stored.
 * An unknown artifact is MANIFEST. A missing slice is MANIFEST and clears
 * the usable bit. This does not write, decrypt, broadcast, or move bytes.
 */
bool SwarmPiecePipeResume(SwarmPiecePipeManifestBook& manifests, const SwarmPiecePipeStore& store, const std::string& artifact, std::string& err);

/**
 * True only after a successful Resume whose slices are all still stored.
 * A manifest that has not been resumed is not usable.
 */
bool SwarmPiecePipeUsable(const SwarmPiecePipeManifestBook& manifests, const SwarmPiecePipeStore& store, const std::string& artifact);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_RESUME_H
