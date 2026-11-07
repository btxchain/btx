// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACT_OFFER_H
#define BITCOIN_MODELNET_SWARM_ARTIFACT_OFFER_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Local piece offers. A negative index is INDEX and is not stored.
 * The same bytes at an index are REPLAY. Different bytes at an index are
 * CONFLICT and the first bytes stay. A missing index is allowed here.
 * Recording an offer does not move bytes across a network.
 */
class ArtifactOffers {
public:
    bool Offer(int64_t index, const std::string& bytes, std::string& err);

    const std::string* Find(int64_t index) const;
    const std::map<int64_t, std::string>& table() const { return m_offers; }
    std::size_t count() const { return m_offers.size(); }

private:
    std::map<int64_t, std::string> m_offers;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACT_OFFER_H
