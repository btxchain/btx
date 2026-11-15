// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/leader.h>

namespace modelnet {

bool LeaseWorkLeader::right() const
{
    return m_right;
}

bool LeaseWorkLeader::claimed() const
{
    return m_right;
}

const std::string& LeaseWorkLeader::worker() const
{
    return m_worker;
}

bool LeaseWorkLeader::Claim(const std::string& worker)
{
    if (m_right || worker.empty()) return false;
    m_worker = worker;
    m_right = true;
    return true;
}

void LeaseWorkLeader::Clear()
{
    m_worker.clear();
    m_right = false;
}

} // namespace modelnet
