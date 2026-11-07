// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_traincohort/cohort.h>

#include <modelnet/swarm_cycle.h>
#include <modelnet/swarm_traincohort/average.h>
#include <modelnet/swarm_traincohort/error.h>
#include <modelnet/swarm_traincohort/remote.h>
#include <modelnet/swarm_traincohort/step.h>
#include <modelnet/training_integer.h>

namespace modelnet {

bool SwarmTrainCohort::AddMember(const std::string& id, std::string& err)
{
    return AddCohortMember(m_members, id, err);
}

bool SwarmTrainCohort::Grant(const std::string& dataset, bool authorized, bool withdrawn, std::string& err)
{
    return GrantCohortDataset(m_grants, dataset, authorized, withdrawn, err);
}

bool SwarmTrainCohort::Withdraw(const std::string& dataset, std::string& err)
{
    return WithdrawCohortDataset(m_grants, dataset, err);
}

bool SwarmTrainCohort::LocalStep(const std::string& id, std::string& err)
{
    TrainCohortMember* member = FindCohortMember(m_members, id);
    if (member == nullptr) {
        err = COHORT_MEMBER;
        return false;
    }
    if (!CohortGrantLive(m_grants)) {
        err = COHORT_DATASET;
        return false;
    }
    return CohortLocalStep(*member, err);
}

bool SwarmTrainCohort::OfferRemote(const std::string& id, uint64_t remote_step, const std::string& hash, std::string& err)
{
    TrainCohortMember* member = FindCohortMember(m_members, id);
    if (member == nullptr) {
        err = COHORT_MEMBER;
        return false;
    }
    return CohortOfferRemote(*member, remote_step, hash, err);
}

bool SwarmTrainCohort::Average(std::string& err) const
{
    return CohortAverage(err);
}

bool SwarmTrainCohort::gpu() const
{
    return false;
}

uint64_t SwarmTrainCohort::bytes_moved() const
{
    return 0;
}

size_t SwarmTrainCohort::MemberCount() const
{
    return m_members.size();
}

bool SwarmTrainCohort::HasMember(const std::string& id) const
{
    return FindCohortMember(m_members, id) != nullptr;
}

uint64_t SwarmTrainCohort::MemberStep(const std::string& id) const
{
    const TrainCohortMember* member = FindCohortMember(m_members, id);
    if (member == nullptr) return 0;
    return member->step;
}

std::string SwarmTrainCohort::MemberHash(const std::string& id) const
{
    const TrainCohortMember* member = FindCohortMember(m_members, id);
    if (member == nullptr) return {};
    return member->state_hash;
}

bool SwarmTrainCohort::HasPending(const std::string& id) const
{
    const TrainCohortMember* member = FindCohortMember(m_members, id);
    return member != nullptr && member->pending;
}

std::string SwarmTrainCohort::PendingHash(const std::string& id) const
{
    const TrainCohortMember* member = FindCohortMember(m_members, id);
    if (member == nullptr || !member->pending) return {};
    return member->pending_hash;
}

bool SwarmTrainCohort::DatasetRecorded(const std::string& dataset) const
{
    return FindCohortGrant(m_grants, dataset) != nullptr;
}

bool SwarmTrainCohort::DatasetWithdrawn(const std::string& dataset) const
{
    const TrainCohortGrant* grant = FindCohortGrant(m_grants, dataset);
    return grant != nullptr && grant->withdrawn;
}

bool SwarmTrainCohort::LiveGrant() const
{
    return CohortGrantLive(m_grants);
}

} // namespace modelnet
