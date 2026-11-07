// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/evaluate.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationEvaluate::Apply(SwarmGenerationCommitment& commitment, const std::string& candidate_id,
                                    const std::string& author, const std::string& evaluator,
                                    const std::string& author_domain, const std::string& evaluator_domain,
                                    bool author_sees_holdout, bool safety_regression, bool broad_regression,
                                    std::string& err) const
{
    if (author == evaluator) {
        return SwarmGenerationFail(err, kSwarmGenerationSelf);
    }
    if (author_domain == evaluator_domain) {
        return SwarmGenerationFail(err, kSwarmGenerationNotQuorum);
    }
    if (author_sees_holdout) {
        return SwarmGenerationFail(err, kSwarmGenerationHoldout);
    }
    if (safety_regression) {
        return SwarmGenerationFail(err, kSwarmGenerationSafety);
    }
    if (broad_regression) {
        return SwarmGenerationFail(err, kSwarmGenerationRegression);
    }
    SwarmGenerationReport report;
    report.candidate_id = candidate_id;
    report.author = author;
    report.evaluator = evaluator;
    report.author_domain = author_domain;
    report.evaluator_domain = evaluator_domain;
    report.author_sees_holdout = false;
    report.safety_regression = false;
    report.broad_regression = false;
    commitment.add(std::move(report));
    return SwarmGenerationOk(err);
}

} // namespace modelnet
