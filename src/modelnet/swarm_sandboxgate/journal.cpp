// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/journal.h>

#include <modelnet/swarm_sandboxgate/record.h>

#include <cstddef>
#include <vector>

namespace modelnet {

std::size_t SwarmSandboxGateJournal::size() const
{
    return m_actions.size();
}

bool SwarmSandboxGateJournal::record(const SwarmSandboxGateAction& action)
{
    if (!SwarmSandboxGateActionUsable(action)) return false;
    m_actions.push_back(action);
    return true;
}

} // namespace modelnet
