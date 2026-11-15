// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/experience.h>

#include <modelnet/swarm_experience/error.h>
#include <modelnet/swarm_experience/limits.h>
#include <modelnet/swarm_experience/offer.h>
#include <modelnet/swarm_experience/reward.h>

namespace modelnet {

bool SwarmExperience::Store(const std::string& id, const std::string& kind, int64_t outcome_ppm, std::string& err)
{
    return m_store.Insert(id, kind, outcome_ppm, err);
}

int SwarmExperience::reward(const std::string& id) const
{
    return ExperienceReward(m_store.Find(id));
}

void SwarmExperience::Enqueue()
{
    m_queue.Enqueue(m_store.rows());
}

bool SwarmExperience::TrainFrom(const std::string& id, std::string& err)
{
    ExperienceRow* row = m_store.Find(id);
    if (row == nullptr) {
        err = kExperienceTrajectory;
        return false;
    }
    return MarkExperienceOffered(*row, err);
}

bool SwarmExperience::offered(const std::string& id) const
{
    const ExperienceRow* row = m_store.Find(id);
    return row != nullptr && row->offered;
}

uint64_t SwarmExperience::bytes_moved() const
{
    return kExperienceBytesMoved;
}

bool SwarmExperience::gpu() const
{
    return false;
}

bool SwarmExperience::private_stored() const
{
    return m_store.private_stored();
}

} // namespace modelnet
