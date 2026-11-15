// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DATASETGATE_H
#define BTX_MODELNET_SWARM_DATASETGATE_H

#include <set>
#include <string>

namespace modelnet {

/**
 * Local record of datasets that have started training.
 *
 * An empty dataset is DATASET and stores nothing. A dataset already
 * started is REPLAY and leaves the first row. Otherwise Grant calls
 * SwarmStartTraining. A false result stores nothing and returns false.
 * A true result stores the dataset as started and returns true.
 *
 * A withdrawn dataset does not start training.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmDatasetGate {
public:
    bool Grant(const std::string& dataset, bool authorized, bool withdrawn, std::string& err);
    bool started(const std::string& dataset) const;

private:
    std::set<std::string> m_started;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DATASETGATE_H
