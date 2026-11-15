// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/plan.h>

namespace modelnet {

bool SwarmEvaluationPlanBook::contains(const std::string& experiment) const
{
    return m_rows.find(experiment) != m_rows.end();
}

bool SwarmEvaluationPlanBook::precommitted(const std::string& experiment) const
{
    const auto it = m_rows.find(experiment);
    if (it == m_rows.end()) {
        return false;
    }
    return it->second.precommitted;
}

std::string SwarmEvaluationPlanBook::suite_of(const std::string& experiment) const
{
    const auto it = m_rows.find(experiment);
    if (it == m_rows.end()) {
        return std::string{};
    }
    return it->second.suite;
}

void SwarmEvaluationPlanBook::open(const std::string& experiment)
{
    if (experiment.empty() || contains(experiment)) {
        return;
    }
    SwarmEvaluationPlan plan;
    plan.experiment = experiment;
    plan.suite.clear();
    plan.precommitted = false;
    plan.distinct_evaluators = kSwarmEvaluationDistinctEvaluators;
    plan.distinct_domains = kSwarmEvaluationDistinctDomains;
    m_rows.emplace(experiment, plan);
}

bool SwarmEvaluationPlanBook::commit(const std::string& experiment, const std::string& suite)
{
    if (experiment.empty() || suite.empty()) {
        return false;
    }
    auto it = m_rows.find(experiment);
    if (it == m_rows.end()) {
        return false;
    }
    if (it->second.precommitted) {
        return false;
    }
    it->second.suite = suite;
    it->second.precommitted = true;
    it->second.distinct_evaluators = kSwarmEvaluationDistinctEvaluators;
    it->second.distinct_domains = kSwarmEvaluationDistinctDomains;
    return true;
}

} // namespace modelnet
