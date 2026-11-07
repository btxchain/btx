// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/suite.h>

namespace modelnet {

bool SwarmEvaluationSuiteBook::committed(const std::string& experiment) const
{
    return m_rows.find(experiment) != m_rows.end();
}

std::string SwarmEvaluationSuiteBook::suite_of(const std::string& experiment) const
{
    const auto it = m_rows.find(experiment);
    if (it == m_rows.end()) {
        return std::string{};
    }
    return it->second.suite;
}

bool SwarmEvaluationSuiteBook::store(const std::string& experiment, const std::string& suite)
{
    if (experiment.empty() || suite.empty() || committed(experiment)) {
        return false;
    }
    SwarmEvaluationSuite row;
    row.experiment = experiment;
    row.suite = suite;
    m_rows.emplace(experiment, row);
    return true;
}

} // namespace modelnet
