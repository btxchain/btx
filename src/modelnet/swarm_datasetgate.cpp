// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_datasetgate.h>

#include <modelnet/swarm_cycle.h>

namespace modelnet {

bool SwarmDatasetGate::Grant(const std::string& dataset, bool authorized, bool withdrawn, std::string& err)
{
    if (dataset.empty()) {
        err = "DATASET";
        return false;
    }
    if (m_started.find(dataset) != m_started.end()) {
        err = "REPLAY";
        return false;
    }
    if (!SwarmStartTraining(authorized, withdrawn, err)) {
        return false;
    }
    m_started.insert(dataset);
    return true;
}

bool SwarmDatasetGate::started(const std::string& dataset) const
{
    return m_started.find(dataset) != m_started.end();
}

} // namespace modelnet
