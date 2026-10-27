// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revokelist.h>

namespace modelnet {

bool SwarmRevokeList::Revoke(const std::string& member, std::string& err)
{
    if (member.empty()) {
        err = "MEMBER";
        return false;
    }
    if (m_revoked.find(member) != m_revoked.end()) {
        err = "REPLAY";
        return false;
    }
    m_revoked.insert(member);
    err.clear();
    return true;
}

bool SwarmRevokeList::Read(const std::string& member, const std::string& page, std::string& err)
{
    if (member.empty() || page.empty()) {
        err = "PAGE";
        return false;
    }
    // A revoked member reads no later page. Do not record the read.
    if (m_revoked.find(member) != m_revoked.end()) {
        err = "NOT_READ";
        return false;
    }
    m_reads.insert(std::make_pair(member, page));
    err.clear();
    return true;
}

bool SwarmRevokeList::revoked(const std::string& member) const
{
    return m_revoked.find(member) != m_revoked.end();
}

int64_t SwarmRevokeList::bytes_moved() const
{
    return 0;
}

} // namespace modelnet
