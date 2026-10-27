// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_REGRESSION_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_REGRESSION_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Regression report for one candidate.
 * code is SAFETY or REGRESSION. The row is not an accepting report.
 * Promoting a different candidate does not delete this row. There is
 * no erase method on the book.
 */
struct SwarmEvaluationRegression {
    std::string experiment;
    std::string candidate;
    std::string author;
    std::string evaluator;
    std::string author_domain;
    std::string evaluator_domain;
    std::string code;
};

/**
 * Regression reports for the population.
 * add appends a row and never replaces or drops an earlier row.
 * contains and count_for are per candidate. A later promotion of
 * another candidate does not change this book.
 */
class SwarmEvaluationRegressionBook {
public:
    void add(const SwarmEvaluationRegression& report);
    bool contains(const std::string& candidate) const;
    std::size_t count_for(const std::string& candidate) const;
    std::size_t size() const;

private:
    std::vector<SwarmEvaluationRegression> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_REGRESSION_H
