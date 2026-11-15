// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_intcycle/swarm_intcycle.h>

#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>
#include <utility>

namespace modelnet {

bool SwarmIntCycle::Run(uint64_t steps, std::string& err)
{
    if (steps < 1) {
        err = SWARM_INTCYCLE_STEPS;
        return false;
    }
    // Step on a copy so a failed Run leaves the stored trainer, hash, and
    // step count unchanged. IntegerTrainer::Run is the only stepper.
    IntegerTrainer advanced = m_trainer;
    if (!advanced.Run(steps, err)) return false;
    m_trainer = std::move(advanced);
    m_state_hash = IntegerStateHash(m_trainer.State());
    m_steps = m_trainer.State().step;
    err.clear();
    return true;
}

bool SwarmIntCycle::Resume(const IntegerState& checkpoint, std::string& err)
{
    IntegerTrainer advanced = m_trainer;
    if (!advanced.Resume(checkpoint, err)) return false;
    m_trainer = std::move(advanced);
    m_state_hash = IntegerStateHash(m_trainer.State());
    m_steps = m_trainer.State().step;
    err.clear();
    return true;
}

bool SwarmIntCycle::GpuRun(uint64_t, std::string& err)
{
    err = SWARM_INTCYCLE_ENGINE_ABSENT;
    return false;
}

bool SwarmIntCycle::ExportGrad(std::string& err)
{
    err = SWARM_INTCYCLE_NOT_EXPORTED;
    return false;
}

uint64_t SwarmIntCycle::steps() const
{
    return m_steps;
}

const std::string& SwarmIntCycle::state_hash() const
{
    return m_state_hash;
}

bool SwarmIntCycle::gpu() const
{
    return false;
}

bool SwarmIntCycle::distributed() const
{
    return false;
}

bool SwarmIntCycle::launched() const
{
    return false;
}

bool SwarmIntCycle::broadcast() const
{
    return false;
}

std::string SwarmIntCycle::automatic_spend() const
{
    return "0";
}

int64_t SwarmIntCycle::atoms_moved() const
{
    return 0;
}

int64_t SwarmIntCycle::bytes_moved() const
{
    return 0;
}

const IntegerState& SwarmIntCycle::State() const
{
    return m_trainer.State();
}

} // namespace modelnet
