// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/remedy.h>

namespace modelnet {

bool SwarmRemedy::Open(int sequence, unsigned char fill, std::string& err)
{
    return m_book.Open(sequence, fill, err);
}

bool SwarmRemedy::Supersede(int sequence, unsigned char fill, std::string& err)
{
    return m_book.Supersede(sequence, fill, err);
}

bool SwarmRemedy::Revoke(const std::string& member, std::string& err)
{
    return m_members.Revoke(member, err);
}

bool SwarmRemedy::Read(const std::string& member, std::string& err)
{
    return m_members.Read(member, err);
}

std::vector<unsigned char> SwarmRemedy::Script(const std::vector<unsigned char>& secret_hash,
                                               const std::vector<unsigned char>& counterparty_pubkey, std::string& err)
{
    return m_leaf.Store(secret_hash, counterparty_pubkey, err);
}

SwarmRemedyReport SwarmRemedy::Watch(int observed_sequence, int height, int refund_height) const
{
    const SwarmRevocation& revocation = m_book.has_prior() ? m_book.prior() : m_book.current();
    return m_watch.Observe(observed_sequence, m_book.sequence(), height, refund_height, revocation);
}

} // namespace modelnet
