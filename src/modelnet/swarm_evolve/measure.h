// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLVE_MEASURE_H
#define BITCOIN_MODELNET_SWARM_EVOLVE_MEASURE_H

#include <modelnet/swarm_evalengine.h>
#include <modelnet/swarm_evolution.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One judge report for the generation subject.
 * rotating false is a fixed holdout.
 */
struct SwarmEvolveScoreReport {
    std::string author;
    std::string subject;
    std::string domain;
    int64_t score{0};
    bool independent{false};
    bool rotating{false};
};

/**
 * Measure gate. Submit requires a trained generation, then SwarmEvalEngine.
 * Author equal to the subject is NOT_SCORED. independent false is HELD.
 * A fixed holdout is NOT_ROTATING. Acceptance is SwarmEvalEngine::Accepted
 * and SwarmQuorum of two authors and two domains. Scores are stored as
 * submitted. Their mean is not computed and is not a pass.
 */
class SwarmEvolveMeasure {
public:
    void SetSubject(std::string subject);
    void SetTrained(bool trained);
    void Reset();

    bool Submit(const SwarmEvolveScoreReport& report, std::string& err);
    bool Accepted() const;
    const std::vector<int64_t>& Scores() const { return m_scores; }

private:
    std::string m_subject;
    bool m_trained{false};
    SwarmEvalEngine m_engine;
    std::vector<SwarmEvaluator> m_evaluators;
    std::vector<int64_t> m_scores;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLVE_MEASURE_H
