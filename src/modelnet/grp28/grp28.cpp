// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp28/grp28.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_paycycle/codes.h>
#include <modelnet/swarm_settlebuild/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Grp28::OpenExperiment(const std::string& id, std::string& err)
{
    return m_eval.OpenExperiment(id, err);
}

bool Grp28::BindCandidate(const std::string& experiment, const std::string& candidate, std::string& err)
{
    return m_eval.BindCandidate(experiment, candidate, err);
}

bool Grp28::CommitSuite(const std::string& experiment, const std::string& suite, std::string& err)
{
    return m_eval.CommitSuite(experiment, suite, err);
}

bool Grp28::Report(const std::string& experiment,
                   const std::string& candidate,
                   const std::string& author,
                   const std::string& evaluator,
                   const std::string& author_domain,
                   const std::string& evaluator_domain,
                   bool author_sees_holdout,
                   bool safety_regression,
                   bool broad_regression,
                   std::string& err)
{
    return m_eval.Report(experiment, candidate, author, evaluator, author_domain, evaluator_domain,
                         author_sees_holdout, safety_regression, broad_regression, err);
}

bool Grp28::Promote(const std::string& candidate, std::string& err)
{
    return m_eval.Promote(candidate, err);
}

bool Grp28::Stage(const std::string& channel, const std::string& candidate, const std::string& policy, std::string& err)
{
    return m_eval.Stage(channel, candidate, policy, err);
}

bool Grp28::Adopt(const std::string& channel, std::string& err)
{
    return m_eval.Adopt(channel, err);
}

bool Grp28::OpenChannel(const std::string& channel, const std::string& pool_a, const std::string& pool_b, std::string& err)
{
    return m_economy.Open(channel, pool_a, pool_b, err);
}

bool Grp28::PayWork(const std::string& pool, const std::string& work, const std::string& worker, std::string& err)
{
    const bool paid = m_economy.PayWork(pool, work, worker, err);
    if (err == SWARM_PAYCYCLE_HELD) {
        err = SWARM_PAYCYCLE_HELD;
        return false;
    }
    return paid;
}

bool Grp28::Settle(std::string& err)
{
    const bool settled = m_economy.Settle(err);
    if (settled || err == NIFDT_UNQUALIFIED || err == kSwarmSettleBuildUnqualified) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    return false;
}

bool Grp28::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

int64_t Grp28::atoms_moved() const
{
    return m_economy.atoms_moved() + static_cast<int64_t>(m_eval.atoms_moved());
}

} // namespace modelnet
