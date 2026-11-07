// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/earlyhalt.h>

#include <modelnet/swarm_earlyhalt/open.h>
#include <modelnet/swarm_earlyhalt/promote.h>
#include <modelnet/swarm_earlyhalt/step.h>

namespace modelnet {

bool SwarmEarlyHalt::Open(int64_t budget, std::string& err)
{
    return SwarmEarlyHaltOpen{}.Apply(m_seat, m_remain, budget, err);
}

bool SwarmEarlyHalt::Step(int64_t score, std::string& err)
{
    return SwarmEarlyHaltStep{}.Apply(m_seat, m_remain, m_score, m_mark, score, err);
}

bool SwarmEarlyHalt::Promote(std::string& err) const
{
    return SwarmEarlyHaltPromote{}.Apply(m_mark, m_score, err);
}

bool SwarmEarlyHalt::PromoteRealm(std::string& err) const
{
    return m_realm.Promote(err);
}

} // namespace modelnet
