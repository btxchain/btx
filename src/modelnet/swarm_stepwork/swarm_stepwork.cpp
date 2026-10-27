// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stepwork/swarm_stepwork.h>

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_stepwork/gpu.h>
#include <modelnet/swarm_stepwork/offer.h>
#include <modelnet/swarm_stepwork/record.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmStepWork::Record(const std::string& id, int64_t steps, bool is_private, std::string& err)
{
    return SwarmStepWorkRecord(m_cycle, m_experience, id, steps, is_private, err);
}

bool SwarmStepWork::Offer(const std::string& id, std::string& err)
{
    return SwarmStepWorkOffer(m_experience, id, err);
}

bool SwarmStepWork::GpuRecord(const std::string& id, int64_t steps, std::string& err)
{
    return SwarmStepWorkRefuseGpu(id, steps, err);
}

const std::string& SwarmStepWork::state_hash() const
{
    return m_cycle.state_hash();
}

int SwarmStepWork::reward_of(const std::string& id) const
{
    return m_experience.reward(id);
}

bool SwarmStepWork::offered(const std::string& id) const
{
    return m_experience.offered(id);
}

std::size_t SwarmStepWork::queued_count() const
{
    return m_experience.queued().size();
}

bool SwarmStepWork::gpu() const
{
    return m_cycle.gpu() || m_experience.gpu();
}

bool SwarmStepWork::private_stored() const
{
    return m_experience.private_stored();
}

std::size_t SwarmStepWork::size() const
{
    return m_experience.size();
}

} // namespace modelnet
