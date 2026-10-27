// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TRAINCOHORT_GRANT_H
#define BITCOIN_MODELNET_SWARM_TRAINCOHORT_GRANT_H

#include <string>
#include <vector>

namespace modelnet {

/** A dataset name recorded only after SwarmStartTraining accepts it. */
struct TrainCohortGrant {
    std::string dataset;
    bool withdrawn{false};
};

bool GrantCohortDataset(std::vector<TrainCohortGrant>& grants, const std::string& dataset, bool authorized, bool withdrawn, std::string& err);

bool WithdrawCohortDataset(std::vector<TrainCohortGrant>& grants, const std::string& dataset, std::string& err);

bool CohortGrantLive(const std::vector<TrainCohortGrant>& grants);

const TrainCohortGrant* FindCohortGrant(const std::vector<TrainCohortGrant>& grants, const std::string& dataset);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TRAINCOHORT_GRANT_H
