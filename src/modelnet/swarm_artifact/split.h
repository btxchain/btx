// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACT_SPLIT_H
#define BITCOIN_MODELNET_SWARM_ARTIFACT_SPLIT_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Catalog of captured artifact pieces at indexes 0..n-1.
 * Split calls SplitModelPieces. An empty capture is ARTIFACT and stores nothing.
 * A layout whose non-last piece is not 32 bytes, or whose last piece is not
 * 1..32 bytes, stores nothing and returns SHORT.
 */
class ArtifactSplit {
public:
    bool Split(const std::string& captured, std::string& err);

    bool ready() const { return m_ready; }
    const std::vector<std::string>& pieces() const { return m_pieces; }

private:
    std::vector<std::string> m_pieces;
    bool m_ready{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACT_SPLIT_H
