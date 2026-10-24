// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_QUALIFY_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_QUALIFY_H

#include <modelnet/swarm_evalengine/regression.h>
#include <modelnet/swarm_evalengine/report.h>

#include <string>

namespace modelnet {

/**
 * A candidate is qualified only when accepting reports include at least
 * two distinct evaluators and two distinct evaluator domains, and no
 * regression report is stored for that candidate.
 * The number of reports is not enough. Two reports from one evaluator
 * do not qualify. Two reports from one evaluator domain do not qualify.
 * There is no vote percentage.
 */
bool SwarmEvaluationIsQualified(const SwarmEvaluationReportBook& reports,
                                const SwarmEvaluationRegressionBook& regressions,
                                const std::string& candidate);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_QUALIFY_H
