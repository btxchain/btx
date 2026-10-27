// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hashlock/hashlock.h>

namespace modelnet {

bool SwarmHashlock::Offer(const std::string& id, const std::vector<unsigned char>& payment_hash, std::string& err)
{
    return m_offers.Offer(id, payment_hash, err);
}

bool SwarmHashlock::Claim(const std::string& id, const std::vector<unsigned char>& preimage, std::string& err)
{
    return m_offers.Claim(id, preimage, err);
}

bool SwarmHashlock::offered(const std::string& id) const
{
    return m_offers.offered(id);
}

bool SwarmHashlock::claimed(const std::string& id) const
{
    return m_offers.claimed(id);
}

int SwarmHashlock::claims(const std::string& id) const
{
    return m_offers.claims(id);
}

bool SwarmHashlock::stored_hash(const std::string& id, std::vector<unsigned char>& out) const
{
    return m_offers.stored_hash(id, out);
}

} // namespace modelnet
