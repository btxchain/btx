// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_traincohort/member.h>

#include <modelnet/swarm_traincohort/error.h>

#include <utility>

namespace modelnet {

bool AddCohortMember(std::vector<TrainCohortMember>& members, const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = COHORT_MEMBER;
        return false;
    }
    if (FindCohortMember(members, id) != nullptr) {
        err = COHORT_REPLAY;
        return false;
    }
    TrainCohortMember created;
    created.id = id;
    members.push_back(std::move(created));
    err.clear();
    return true;
}

TrainCohortMember* FindCohortMember(std::vector<TrainCohortMember>& members, const std::string& id)
{
    for (TrainCohortMember& member : members) {
        if (member.id == id) return &member;
    }
    return nullptr;
}

const TrainCohortMember* FindCohortMember(const std::vector<TrainCohortMember>& members, const std::string& id)
{
    for (const TrainCohortMember& member : members) {
        if (member.id == id) return &member;
    }
    return nullptr;
}

} // namespace modelnet
