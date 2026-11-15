// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/store.h>

#include <modelnet/swarm_experience/error.h>
#include <modelnet/swarm_experience/kind.h>
#include <modelnet/swarm_experience/limits.h>

#include <utility>

namespace modelnet {

bool ExperienceStore::Insert(const std::string& id, const std::string& kind, int64_t outcome_ppm, std::string& err)
{
    if (id.empty()) {
        err = kExperienceTrajectory;
        return false;
    }
    if (!ExperienceKindAllowed(kind, err)) {
        return false;
    }
    if (Find(id) != nullptr) {
        err = kExperienceReplay;
        return false;
    }
    if (!ExperienceOutcomeInRange(outcome_ppm)) {
        err = kExperienceRange;
        return false;
    }

    ExperienceRow created;
    created.id = id;
    created.kind = kind;
    created.outcome_ppm = outcome_ppm;
    m_rows.push_back(std::move(created));
    err.clear();
    return true;
}

ExperienceRow* ExperienceStore::Find(const std::string& id)
{
    for (ExperienceRow& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

const ExperienceRow* ExperienceStore::Find(const std::string& id) const
{
    for (const ExperienceRow& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

bool ExperienceStore::private_stored() const
{
    for (const ExperienceRow& row : m_rows) {
        std::string err;
        if (!ExperienceKindAllowed(row.kind, err)) return true;
    }
    return false;
}

} // namespace modelnet
