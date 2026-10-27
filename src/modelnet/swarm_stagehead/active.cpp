// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/active.h>

namespace modelnet {

void SwarmStageActive::assign(const std::string& id)
{
    if (id.empty()) return;
    m_id = id;
}

} // namespace modelnet
