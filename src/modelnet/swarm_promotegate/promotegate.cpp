// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/promotegate.h>

#include <modelnet/swarm_promotegate/begin.h>
#include <modelnet/swarm_promotegate/clear.h>
#include <modelnet/swarm_promotegate/finish.h>
#include <modelnet/swarm_promotegate/interrupt.h>
#include <modelnet/swarm_promotegate/resume.h>
#include <modelnet/swarm_promotegate/rollback.h>

namespace modelnet {

bool SwarmPromoteGate::Begin(const std::string& candidate, std::string& err)
{
    return SwarmPromoteBegin{}.Place(m_staged, candidate, err);
}

bool SwarmPromoteGate::Interrupt(std::string& err)
{
    return SwarmPromoteInterrupt{}.Apply(m_staged, m_flag, err);
}

bool SwarmPromoteGate::Finish(std::string& err)
{
    return SwarmPromoteFinish{}.Apply(m_active, m_memory, m_staged, m_flag, err);
}

bool SwarmPromoteGate::Resume(std::string& err) const
{
    return SwarmPromoteResume{}.Apply(m_flag, err);
}

bool SwarmPromoteGate::Clear(std::string& err)
{
    return SwarmPromoteClear{}.Apply(m_staged, m_flag, err);
}

bool SwarmPromoteGate::Rollback(std::string& err)
{
    return SwarmPromoteRollback{}.Restore(m_active, m_memory, err);
}

bool SwarmPromoteGate::PromoteRealm(std::string& err) const
{
    return m_realm.Promote(err);
}

} // namespace modelnet
