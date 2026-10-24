// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_traincohort/grant.h>

#include <modelnet/swarm_cycle.h>
#include <modelnet/swarm_traincohort/error.h>

#include <utility>

namespace modelnet {

const TrainCohortGrant* FindCohortGrant(const std::vector<TrainCohortGrant>& grants, const std::string& dataset)
{
    for (const TrainCohortGrant& grant : grants) {
        if (grant.dataset == dataset) return &grant;
    }
    return nullptr;
}

namespace {

TrainCohortGrant* FindMutableGrant(std::vector<TrainCohortGrant>& grants, const std::string& dataset)
{
    for (TrainCohortGrant& grant : grants) {
        if (grant.dataset == dataset) return &grant;
    }
    return nullptr;
}

} // namespace

bool GrantCohortDataset(std::vector<TrainCohortGrant>& grants, const std::string& dataset, bool authorized, bool withdrawn, std::string& err)
{
    if (FindCohortGrant(grants, dataset) != nullptr) {
        err = COHORT_REPLAY;
        return false;
    }
    if (!SwarmStartTraining(authorized, withdrawn, err)) {
        return false;
    }
    TrainCohortGrant grant;
    grant.dataset = dataset;
    grant.withdrawn = false;
    grants.push_back(std::move(grant));
    err.clear();
    return true;
}

bool WithdrawCohortDataset(std::vector<TrainCohortGrant>& grants, const std::string& dataset, std::string& err)
{
    TrainCohortGrant* grant = FindMutableGrant(grants, dataset);
    if (grant == nullptr) {
        err = COHORT_DATASET;
        return false;
    }
    grant->withdrawn = true;
    err.clear();
    return true;
}

bool CohortGrantLive(const std::vector<TrainCohortGrant>& grants)
{
    for (const TrainCohortGrant& grant : grants) {
        if (!grant.withdrawn) return true;
    }
    return false;
}

} // namespace modelnet
