// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_SUITE_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_SUITE_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Precommitted suite for one experiment.
 * The suite id is stored once. A second suite id for the same experiment
 * is not stored. Reports are refused until this record exists.
 */
struct SwarmEvaluationSuite {
    std::string experiment;
    std::string suite;
};

/**
 * Suites keyed by experiment id.
 * store refuses an empty suite and an experiment that already has one.
 * The first suite stays. There is no erase.
 */
class SwarmEvaluationSuiteBook {
public:
    bool committed(const std::string& experiment) const;
    std::string suite_of(const std::string& experiment) const;
    bool store(const std::string& experiment, const std::string& suite);

private:
    std::map<std::string, SwarmEvaluationSuite> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_SUITE_H
