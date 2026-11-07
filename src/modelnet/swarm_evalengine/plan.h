// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_PLAN_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_PLAN_H

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Two accepting reports are required. The evaluators must be distinct
 * and the evaluator domains must be distinct. There is no vote percentage.
 */
inline constexpr std::size_t kSwarmEvaluationDistinctEvaluators = 2;
inline constexpr std::size_t kSwarmEvaluationDistinctDomains = 2;

/**
 * Evaluation plan for one experiment.
 * Opened with the experiment. The suite is empty and precommitted is
 * false until CommitSuite. A later suite does not replace the first.
 * Reports are refused while precommitted is false.
 */
struct SwarmEvaluationPlan {
    std::string experiment;
    std::string suite;
    bool precommitted{false};
    std::size_t distinct_evaluators{kSwarmEvaluationDistinctEvaluators};
    std::size_t distinct_domains{kSwarmEvaluationDistinctDomains};
};

/**
 * Plans keyed by experiment id.
 * open keeps the first plan. commit records the first suite and sets
 * precommitted. A second commit leaves the first suite in place.
 */
class SwarmEvaluationPlanBook {
public:
    bool contains(const std::string& experiment) const;
    bool precommitted(const std::string& experiment) const;
    std::string suite_of(const std::string& experiment) const;
    void open(const std::string& experiment);
    bool commit(const std::string& experiment, const std::string& suite);

private:
    std::map<std::string, SwarmEvaluationPlan> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_PLAN_H
