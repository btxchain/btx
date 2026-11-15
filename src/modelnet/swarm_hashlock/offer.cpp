// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock/offer.h>

#include <modelnet/swarm_hashlock/claim.h>

#include <utility>

namespace modelnet {

bool SwarmHashlockOfferBook::Offer(const std::string& id,
                                   const std::vector<unsigned char>& payment_hash,
                                   std::string& err)
{
    if (id.empty()) {
        err = SWARM_HASHLOCK_INVOICE;
        return false;
    }
    if (payment_hash.size() != kSwarmHashlockDigestSize) {
        err = SWARM_HASHLOCK_PREIMAGE;
        return false;
    }
    if (m_offers.find(id) != m_offers.end()) {
        err = SWARM_HASHLOCK_REPLAY;
        return false;
    }
    SwarmHashlockOffer row;
    row.id = id;
    row.payment_hash = payment_hash;
    m_offers.emplace(id, std::move(row));
    err.clear();
    return true;
}

bool SwarmHashlockOfferBook::Claim(const std::string& id,
                                   const std::vector<unsigned char>& preimage,
                                   std::string& err)
{
    const auto it = m_offers.find(id);
    if (it == m_offers.end()) {
        err = SWARM_HASHLOCK_INVOICE;
        return false;
    }
    return SwarmHashlockApplyClaim(it->second, preimage, err);
}

bool SwarmHashlockOfferBook::offered(const std::string& id) const
{
    return m_offers.find(id) != m_offers.end();
}

bool SwarmHashlockOfferBook::claimed(const std::string& id) const
{
    const auto it = m_offers.find(id);
    return it != m_offers.end() && it->second.claimed;
}

int SwarmHashlockOfferBook::claims(const std::string& id) const
{
    return claimed(id) ? 1 : 0;
}

bool SwarmHashlockOfferBook::stored_hash(const std::string& id, std::vector<unsigned char>& out) const
{
    const auto it = m_offers.find(id);
    if (it == m_offers.end()) {
        return false;
    }
    out = it->second.payment_hash;
    return true;
}

} // namespace modelnet
