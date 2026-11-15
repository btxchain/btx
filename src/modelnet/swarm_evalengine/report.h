// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_REPORT_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_REPORT_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One accepting evaluation report.
 * Self scores, same-domain scores, visible holdouts, and regression
 * flags are not stored here. A stored row is an accepting report.
 * The count of rows is not by itself a qualification.
 */
struct SwarmEvaluationReport {
    std::string experiment;
    std::string candidate;
    std::string author;
    std::string evaluator;
    std::string author_domain;
    std::string evaluator_domain;
    bool accepting{true};
};

/**
 * Accepting reports for the population.
 * add appends one accepting row. count_for, distinct_evaluators, and
 * distinct_domains read the rows for one candidate across experiments.
 * There is no erase and no vote percentage.
 */
class SwarmEvaluationReportBook {
public:
    void add(const SwarmEvaluationReport& report);
    std::size_t count_for(const std::string& candidate) const;
    std::size_t distinct_evaluators(const std::string& candidate) const;
    std::size_t distinct_domains(const std::string& candidate) const;

private:
    std::vector<SwarmEvaluationReport> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_REPORT_H
