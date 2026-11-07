// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACT_PIECES_H
#define BITCOIN_MODELNET_SWARM_ARTIFACT_PIECES_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Non-last pieces are exactly 32 bytes. The last piece is 1..32 bytes.
 * A failing layout sets err to SHORT.
 */
bool ArtifactPiecesFit(const std::vector<std::string>& pieces, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACT_PIECES_H
