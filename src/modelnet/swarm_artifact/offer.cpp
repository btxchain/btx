// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifact/offer.h>

#include <modelnet/swarm_artifact/error.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool ArtifactOffers::Offer(int64_t index, const std::string& bytes, std::string& err)
{
    if (index < 0) {
        err = kSwarmArtifactIndex;
        return false;
    }
    const auto found = m_offers.find(index);
    if (found != m_offers.end()) {
        if (found->second == bytes) {
            err = kSwarmArtifactReplay;
            return false;
        }
        err = kSwarmArtifactConflict;
        return false;
    }
    m_offers.emplace(index, bytes);
    err.clear();
    return true;
}

const std::string* ArtifactOffers::Find(int64_t index) const
{
    const auto found = m_offers.find(index);
    if (found == m_offers.end()) return nullptr;
    return &found->second;
}

} // namespace modelnet
