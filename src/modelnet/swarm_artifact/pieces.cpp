// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifact/pieces.h>

#include <modelnet/swarm_artifact/error.h>
#include <modelnet/swarm_artifact/limits.h>

#include <cstddef>

namespace modelnet {

bool ArtifactPiecesFit(const std::vector<std::string>& pieces, std::string& err)
{
    if (pieces.empty()) {
        err = kSwarmArtifactShort;
        return false;
    }
    const std::size_t last = pieces.size() - 1;
    for (std::size_t i = 0; i < pieces.size(); ++i) {
        const std::size_t n = pieces[i].size();
        if (i != last) {
            if (n != kSwarmArtifactPieceBytes) {
                err = kSwarmArtifactShort;
                return false;
            }
            continue;
        }
        if (n < 1 || n > kSwarmArtifactPieceBytes) {
            err = kSwarmArtifactShort;
            return false;
        }
    }
    err.clear();
    return true;
}

} // namespace modelnet
