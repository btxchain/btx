// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/stagehead.h>

#include <modelnet/swarm_stagehead/adopt.h>
#include <modelnet/swarm_stagehead/pin.h>
#include <modelnet/swarm_stagehead/regress.h>
#include <modelnet/swarm_stagehead/rollback.h>
#include <modelnet/swarm_stagehead/stage.h>

namespace modelnet {

bool SwarmStageHead::Stage(const std::string& candidate, std::string& err)
{
    return SwarmStagePlace{}.Place(m_staged, candidate, err);
}

bool SwarmStageHead::Adopt(bool local_compatible, std::string& err)
{
    return SwarmStageAdopt{}.Apply(m_active, m_memory, m_staged, local_compatible, err);
}

bool SwarmStageHead::Rollback(std::string& err)
{
    return SwarmStageRollback{}.Restore(m_active, m_memory, err);
}

bool SwarmStageHead::Pin(std::string& err)
{
    return SwarmStagePin{}.Apply(m_staged, err);
}

bool SwarmStageHead::Regress(std::string& err)
{
    return SwarmStageRegress{}.Apply(m_active, m_memory, err);
}

bool SwarmStageHead::PromoteRealm(std::string& err) const
{
    return m_realm.Promote(err);
}

} // namespace modelnet
