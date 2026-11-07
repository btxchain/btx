// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/qualify.h>

#include <modelnet/swarm_evalengine/plan.h>

namespace modelnet {

bool SwarmEvaluationIsQualified(const SwarmEvaluationReportBook& reports,
                                const SwarmEvaluationRegressionBook& regressions,
                                const std::string& candidate)
{
    if (candidate.empty()) {
        return false;
    }
    if (regressions.contains(candidate)) {
        return false;
    }
    if (reports.distinct_evaluators(candidate) < kSwarmEvaluationDistinctEvaluators) {
        return false;
    }
    if (reports.distinct_domains(candidate) < kSwarmEvaluationDistinctDomains) {
        return false;
    }
    return true;
}

} // namespace modelnet
