// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp27/grp27.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_evalengine/engine.h>
#include <modelnet/swarm_evalengine/codes.h>
#include <modelnet/dt_sockagree/dt_sockagree.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

constexpr char kGrp27Suite[] = "suite";

bool Kept(bool ok, const std::string& err)
{
    return ok || err == kSwarmEvaluationReplay;
}

} // namespace

bool Grp27::Compare(int64_t left, int64_t right, std::string& err)
{
    return m_agree.Compare(left, right, err);
}

bool Grp27::Grade(const std::string& experiment,
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
    if (!Kept(m_eval.OpenExperiment(experiment, err), err)) return false;
    if (!Kept(m_eval.BindCandidate(experiment, candidate, err), err)) return false;
    if (!Kept(m_eval.CommitSuite(experiment, kGrp27Suite, err), err)) return false;
    return m_eval.Report(experiment, candidate, author, evaluator, author_domain, evaluator_domain,
                         author_sees_holdout, safety_regression, broad_regression, err);
}

bool Grp27::agreed() const
{
    return m_agree.agreed();
}

bool Grp27::eval_qualified(const std::string& candidate) const
{
    return m_eval.qualified(candidate);
}

std::string Grp27::classification() const
{
    return DT_SOCKAGREE_CLASSIFICATION;
}

bool Grp27::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp27::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp27::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp27::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
