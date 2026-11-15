// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_disttrain/swarm_disttrain.h>

#include <hash.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmDistTrain::Step(uint64_t steps, std::string& err)
{
    if (steps < 1) {
        err = SWARM_DISTTRAIN_STEPS;
        return false;
    }
    if (!worker_a.Run(steps, err)) {
        return false;
    }
    if (!worker_b.Run(steps, err)) {
        // worker_a has already advanced. Leave the stored witness unchanged.
        return false;
    }
    const std::string& hash_a = worker_a.state_hash();
    const std::string& hash_b = worker_b.state_hash();
    m_witness = HexStr(Hash(hash_a + hash_b));
    err.clear();
    return true;
}

bool SwarmDistTrain::GpuStep(uint64_t, std::string& err)
{
    err = SWARM_DISTTRAIN_ENGINE_ABSENT;
    return false;
}

bool SwarmDistTrain::FsdpStep(uint64_t, std::string& err)
{
    err = SWARM_DISTTRAIN_ENGINE_ABSENT;
    return false;
}

bool SwarmDistTrain::DilocoStep(uint64_t, std::string& err)
{
    err = SWARM_DISTTRAIN_ENGINE_ABSENT;
    return false;
}

bool SwarmDistTrain::ExportGrad(std::string& err)
{
    err = SWARM_DISTTRAIN_NOT_EXPORTED;
    return false;
}

const std::string& SwarmDistTrain::witness() const
{
    return m_witness;
}

uint64_t SwarmDistTrain::steps_done() const
{
    if (!m_witness.empty()) {
        return worker_a.steps() + worker_b.steps();
    }
    // No witness yet. This is 0 when worker_a has not run. If worker_b.Run
    // fails after worker_a.Run succeeds, the count may reflect worker_a.
    return worker_a.steps();
}

bool SwarmDistTrain::gpu() const
{
    return false;
}

bool SwarmDistTrain::distributed_gpu() const
{
    return false;
}

bool SwarmDistTrain::launched() const
{
    return false;
}

bool SwarmDistTrain::broadcast() const
{
    return false;
}

std::string SwarmDistTrain::automatic_spend() const
{
    return "0";
}

int64_t SwarmDistTrain::atoms_moved() const
{
    return 0;
}

} // namespace modelnet
