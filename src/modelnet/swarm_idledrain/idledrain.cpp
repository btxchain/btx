// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/idledrain.h>

#include <modelnet/swarm_idledrain/admit.h>
#include <modelnet/swarm_idledrain/drain.h>
#include <modelnet/swarm_idledrain/open.h>

namespace modelnet {

bool SwarmIdleDrain::Open(std::string& err)
{
    return SwarmIdleDrainOpen{}.Apply(m_seat, m_workers, err);
}

bool SwarmIdleDrain::Admit(std::string& err)
{
    return SwarmIdleDrainAdmit{}.Apply(m_mark, m_workers, err);
}

bool SwarmIdleDrain::Drain(const std::string& reason, std::string& err)
{
    return SwarmIdleDrainDrain{}.Apply(m_mark, m_workers, reason, err);
}

} // namespace modelnet
