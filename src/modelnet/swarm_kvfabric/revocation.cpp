// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/revocation.h>

#include <modelnet/swarm_kvfabric/codes.h>

namespace modelnet {

SwarmKvFabricResult KvFabricRevocation::Revoke(const std::string& member)
{
    if (member.empty()) {
        return KvFabricResult(kKvFabricPage);
    }
    m_revoked.insert(member);
    return KvFabricResult(kKvFabricRevoked);
}

SwarmKvFabricResult KvFabricRevocation::Read(const std::string& member, const std::string& page, bool page_placed)
{
    if (member.empty() || page.empty()) {
        return KvFabricResult(kKvFabricPage);
    }
    if (m_revoked.count(member) != 0 || !page_placed) {
        return KvFabricResult(kKvFabricNotRead);
    }
    m_reads.insert({member, page});
    return KvFabricResult(kKvFabricRead);
}

bool KvFabricRevocation::revoked(const std::string& member) const
{
    return m_revoked.count(member) != 0;
}

bool KvFabricRevocation::recorded(const std::string& member, const std::string& page) const
{
    return m_reads.count({member, page}) != 0;
}

} // namespace modelnet
