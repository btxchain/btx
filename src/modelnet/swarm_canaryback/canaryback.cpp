// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_canaryback/canaryback.h>

#include <modelnet/swarm_canaryback/adopt.h>
#include <modelnet/swarm_canaryback/graduate.h>
#include <modelnet/swarm_canaryback/mine.h>
#include <modelnet/swarm_canaryback/regress.h>
#include <modelnet/swarm_canaryback/stage.h>

namespace modelnet {

bool SwarmCanaryBack::Stage(const std::string& id, std::string& err)
{
    return SwarmCanaryBackStage{}.Apply(m_candidate, id, err);
}

bool SwarmCanaryBack::Adopt(std::string& err)
{
    return SwarmCanaryBackAdopt{}.Apply(m_active, m_candidate, m_prior, err);
}

bool SwarmCanaryBack::Regress(std::string& err)
{
    return SwarmCanaryBackRegress{}.Apply(m_active, m_candidate, m_prior, err);
}

bool SwarmCanaryBack::Graduate(std::string& err) const
{
    return SwarmCanaryBackGraduate{}.Apply(err);
}

bool SwarmCanaryBack::Mine(std::string& err) const
{
    return SwarmCanaryBackMine{}.Apply(err);
}

} // namespace modelnet
