// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifact/split.h>

#include <modelnet/swarm_artifact/error.h>
#include <modelnet/swarm_artifact/pieces.h>
#include <modelnet/training_integer.h>

#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool ArtifactSplit::Split(const std::string& captured, std::string& err)
{
    std::vector<std::string> pieces;
    std::string split_err;
    const bool split_ok = SplitModelPieces(captured, pieces, split_err);
    if (captured.empty()) {
        err = kSwarmArtifactArtifact;
        return false;
    }
    if (!split_ok) {
        err = split_err;
        return false;
    }
    if (!ArtifactPiecesFit(pieces, err)) return false;

    m_pieces = std::move(pieces);
    m_ready = true;
    err.clear();
    return true;
}

} // namespace modelnet
