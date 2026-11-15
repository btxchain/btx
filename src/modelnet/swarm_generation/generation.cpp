// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/generation.h>

#include <modelnet/swarm_generation/adopt.h>
#include <modelnet/swarm_generation/allocate.h>
#include <modelnet/swarm_generation/compare.h>
#include <modelnet/swarm_generation/continue.h>
#include <modelnet/swarm_generation/distribute.h>
#include <modelnet/swarm_generation/eligible.h>
#include <modelnet/swarm_generation/evaluate.h>
#include <modelnet/swarm_generation/execute.h>
#include <modelnet/swarm_generation/identify.h>
#include <modelnet/swarm_generation/keepnegative.h>
#include <modelnet/swarm_generation/keepspecialist.h>
#include <modelnet/swarm_generation/produce.h>
#include <modelnet/swarm_generation/promote.h>
#include <modelnet/swarm_generation/propose.h>
#include <modelnet/swarm_generation/provenance.h>
#include <modelnet/swarm_generation/stage.h>
#include <modelnet/swarm_generation/task.h>

namespace modelnet {

bool SwarmGenerationEngine::Identify(const std::string& weakness, std::string& err)
{
    return SwarmGenerationIdentify{}.Apply(m_strategy, m_lineage.cycle(), weakness, err);
}

bool SwarmGenerationEngine::Propose(const std::string& experiment, std::string& err)
{
    return SwarmGenerationPropose{}.Apply(m_strategy, m_frontier, experiment, err);
}

bool SwarmGenerationEngine::Eligible(bool license_allows, bool operator_grant, std::string& err)
{
    return SwarmGenerationEligible{}.Apply(m_strategy, license_allows, operator_grant, err);
}

bool SwarmGenerationEngine::Allocate(int slots, int exploration_percent, std::string& err)
{
    return SwarmGenerationAllocate{}.Apply(m_strategy, slots, exploration_percent, err);
}

bool SwarmGenerationEngine::SelectTask(const std::string& task, bool data_grant, std::string& err)
{
    return SwarmGenerationSelectTask{}.Apply(m_strategy, task, data_grant, err);
}

bool SwarmGenerationEngine::Execute(std::string& err)
{
    return SwarmGenerationExecute{}.Apply(m_training, m_lineage, err);
}

bool SwarmGenerationEngine::Produce(const std::string& parent, const std::string& recipe, const std::string& weights, const std::string& nonce, std::string& err)
{
    return SwarmGenerationProduce{}.Apply(m_population, m_challengers, parent, recipe, weights, nonce, err);
}

bool SwarmGenerationEngine::VerifyProvenance(const std::string& candidate_id, const std::string& parent, std::string& err)
{
    return SwarmGenerationProvenance{}.Apply(m_population, candidate_id, parent, err);
}

bool SwarmGenerationEngine::Evaluate(const std::string& candidate_id, const std::string& author, const std::string& evaluator,
                               const std::string& author_domain, const std::string& evaluator_domain, bool author_sees_holdout,
                               bool safety_regression, bool broad_regression, std::string& err)
{
    return SwarmGenerationEvaluate{}.Apply(m_commitment, candidate_id, author, evaluator, author_domain, evaluator_domain,
                                           author_sees_holdout, safety_regression, broad_regression, err);
}

bool SwarmGenerationEngine::KeepNegative(const std::string& result, std::string& err)
{
    return SwarmGenerationKeepNegative{}.Apply(m_negatives, result, err);
}

bool SwarmGenerationEngine::Compare(const std::string& left, const std::string& right, bool compatible, std::string& err)
{
    return SwarmGenerationCompare{}.Apply(m_branches, m_performance, left, right, compatible, err);
}

bool SwarmGenerationEngine::Promote(const std::string& candidate_id, std::string& err)
{
    return SwarmGenerationPromote{}.Apply(m_commitment, m_certificates, m_lineage, candidate_id, err);
}

bool SwarmGenerationEngine::KeepSpecialist(const std::string& name, const std::string& candidate_id, std::string& err)
{
    return SwarmGenerationKeepSpecialist{}.Apply(m_specialists, name, candidate_id, err);
}

bool SwarmGenerationEngine::Distribute(const std::string& candidate_id, std::string& err)
{
    return SwarmGenerationDistribute{}.Apply(m_population, candidate_id, err);
}

bool SwarmGenerationEngine::Stage(const std::string& channel, const std::string& candidate_id, const std::string& policy, std::string& err)
{
    return SwarmGenerationStage{}.Apply(m_channels, m_commitment, channel, candidate_id, policy, err);
}

bool SwarmGenerationEngine::Adopt(const std::string& channel, std::string& err)
{
    return SwarmGenerationAdopt{}.Apply(m_channels, m_adoptions, m_rollbacks, channel, err);
}

bool SwarmGenerationEngine::Continue(std::string& err)
{
    return SwarmGenerationContinue{}.Apply(m_lineage, m_channels, m_commitment, err);
}

} // namespace modelnet
