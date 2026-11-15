// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/checkpoint.h>

#include <string>

namespace modelnet {

bool SwarmFaultCheckpoint::Keep(const std::string& id, std::string& err)
{
    m_id = id;
    m_kept = true;
    err.clear();
    return true;
}

bool SwarmFaultCheckpoint::kept() const
{
    return m_kept;
}

std::string SwarmFaultCheckpoint::id() const
{
    return m_id;
}

} // namespace modelnet
