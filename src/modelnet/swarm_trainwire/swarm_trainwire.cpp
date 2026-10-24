// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_trainwire/swarm_trainwire.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmTrainWire::Step(uint64_t steps, std::string& err)
{
    if (steps < 1) {
        err = SWARM_TRAINWIRE_STEPS;
        return false;
    }
    if (!m_trainer.Step(steps, err)) {
        return false;
    }
    m_trained = true;
    return true;
}

bool SwarmTrainWire::GpuStep(uint64_t, std::string& err)
{
    err = SWARM_TRAINWIRE_ENGINE_ABSENT;
    return false;
}

bool SwarmTrainWire::Recover(std::string& err)
{
    if (!m_trained) {
        err = SWARM_TRAINWIRE_NOT_RESUMED;
        return false;
    }
    err.clear();
    return true;
}

const std::string& SwarmTrainWire::witness() const
{
    return m_trainer.witness();
}

uint64_t SwarmTrainWire::steps_done() const
{
    return m_trainer.steps_done();
}

bool SwarmTrainWire::trained() const
{
    return m_trained;
}

bool SwarmTrainWire::launched() const
{
    return false;
}

bool SwarmTrainWire::gpu() const
{
    return false;
}

bool SwarmTrainWire::distributed_gpu() const
{
    return false;
}

bool SwarmTrainWire::broadcast() const
{
    return false;
}

std::string SwarmTrainWire::automatic_spend() const
{
    return "0";
}

int64_t SwarmTrainWire::atoms_moved() const
{
    return 0;
}

} // namespace modelnet
