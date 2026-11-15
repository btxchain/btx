// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TRAINCOHORT_COHORT_H
#define BITCOIN_MODELNET_SWARM_TRAINCOHORT_COHORT_H

#include <modelnet/swarm_traincohort/grant.h>
#include <modelnet/swarm_traincohort/member.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local record of integer-trainer members under one dataset grant.
 * Each member starts untrained at step 0. One LocalStep commits that
 * member's step and state_hash after replay matches. A remote offer one
 * step ahead is pending only. Average does not change any member hash.
 * gpu() is false. bytes_moved() is 0.
 */
class SwarmTrainCohort {
public:
    bool AddMember(const std::string& id, std::string& err);
    bool Grant(const std::string& dataset, bool authorized, bool withdrawn, std::string& err);
    bool Withdraw(const std::string& dataset, std::string& err);
    bool LocalStep(const std::string& id, std::string& err);
    bool OfferRemote(const std::string& id, uint64_t remote_step, const std::string& hash, std::string& err);
    bool Average(std::string& err) const;

    bool gpu() const;
    uint64_t bytes_moved() const;

    size_t MemberCount() const;
    bool HasMember(const std::string& id) const;
    uint64_t MemberStep(const std::string& id) const;
    std::string MemberHash(const std::string& id) const;
    bool HasPending(const std::string& id) const;
    std::string PendingHash(const std::string& id) const;
    bool DatasetRecorded(const std::string& dataset) const;
    bool DatasetWithdrawn(const std::string& dataset) const;
    bool LiveGrant() const;

private:
    std::vector<TrainCohortMember> m_members;
    std::vector<TrainCohortGrant> m_grants;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TRAINCOHORT_COHORT_H
