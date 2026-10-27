// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifact/join.h>

#include <modelnet/swarm_artifact/error.h>
#include <modelnet/swarm_artifact/pieces.h>
#include <modelnet/training_integer.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool ArtifactJoin::Join(const std::string& captured,
                        const std::vector<std::string>& pieces,
                        const std::map<int64_t, std::string>& offers,
                        std::string& err)
{
    if (m_joined) {
        err.clear();
        return true;
    }
    if (captured.empty()) {
        err = kSwarmArtifactArtifact;
        return false;
    }

    const int64_t n = static_cast<int64_t>(pieces.size());
    if (n <= 0 || static_cast<int64_t>(offers.size()) != n) {
        err = kSwarmArtifactGap;
        return false;
    }

    std::vector<std::string> ordered;
    ordered.reserve(pieces.size());
    for (int64_t i = 0; i < n; ++i) {
        const auto found = offers.find(i);
        if (found == offers.end()) {
            err = kSwarmArtifactGap;
            return false;
        }
        ordered.push_back(found->second);
    }
    if (!ArtifactPiecesFit(ordered, err)) return false;

    std::string joined;
    if (!JoinModelPieces(ordered, joined, err)) {
        err = kSwarmArtifactGap;
        return false;
    }
    if (joined != captured) {
        err = kSwarmArtifactMismatch;
        return false;
    }

    m_reassembly = std::move(joined);
    m_joined = true;
    err.clear();
    return true;
}

} // namespace modelnet
