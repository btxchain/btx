// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_COMMITMENT_H
#define BITCOIN_MODELNET_SWARM_GENERATION_COMMITMENT_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmGenerationReport {
    std::string candidate_id;
    std::string author;
    std::string evaluator;
    std::string author_domain;
    std::string evaluator_domain;
    bool author_sees_holdout{false};
    bool safety_regression{false};
    bool broad_regression{false};
};

/**
 * Independent evaluation commitments.
 * qualified() is two distinct evaluators and two distinct domains.
 * A single report is not enough, and a 51 percent tally is not an input.
 */
class SwarmGenerationCommitment {
public:
    void add(SwarmGenerationReport report);
    std::size_t count(const std::string& candidate_id) const;
    bool qualified(const std::string& candidate_id) const;
    const std::vector<SwarmGenerationReport>& reports() const { return m_reports; }

private:
    std::vector<SwarmGenerationReport> m_reports;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_COMMITMENT_H
