// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/nodedefault.h>

namespace modelnet {

bool SwarmNodeDefault::modelnet_on() const
{
    return m_gate.modelnet_on();
}

bool SwarmNodeDefault::DisableModelNet(std::string& err)
{
    return m_gate.DisableModelNet(err);
}

const std::string& SwarmNodeDefault::launch_profile() const
{
    return m_profile.launch_profile();
}

bool SwarmNodeDefault::RenameProfile(const std::string& name, std::string& err)
{
    return m_profile.RenameProfile(name, err);
}

const std::vector<std::string>& SwarmNodeDefault::dns_seeds() const
{
    return m_seeds.dns_seeds();
}

bool SwarmNodeDefault::AddSeed(const std::string& seed, std::string& err)
{
    return m_seeds.AddSeed(seed, err);
}

bool SwarmNodeDefault::training() const
{
    return m_training.training();
}

bool SwarmNodeDefault::EnableTraining(std::string& err)
{
    return m_training.EnableTraining(err);
}

bool SwarmNodeDefault::private_prompts() const
{
    return m_privacy.private_prompts();
}

bool SwarmNodeDefault::EnablePrivate(std::string& err)
{
    return m_privacy.EnablePrivate(err);
}

const std::string& SwarmNodeDefault::automatic_spend() const
{
    return m_spend.automatic_spend();
}

bool SwarmNodeDefault::armed() const
{
    return m_spend.armed();
}

int64_t SwarmNodeDefault::atoms_moved() const
{
    return m_spend.atoms_moved();
}

bool SwarmNodeDefault::ArmSpend(int64_t atoms, bool operator_signed, bool research_key, bool scheduler, std::string& err)
{
    return m_spend.ArmSpend(atoms, operator_signed, research_key, scheduler, err);
}

int SwarmNodeDefault::cpu_threads() const
{
    return m_cpu.cpu_threads();
}

bool SwarmNodeDefault::RaiseThreads(int n, std::string& err)
{
    return m_cpu.RaiseThreads(n, err);
}

int64_t SwarmNodeDefault::vram_mib() const
{
    return m_vram.vram_mib();
}

bool SwarmNodeDefault::ClaimVram(int64_t n, std::string& err)
{
    return m_vram.ClaimVram(n, err);
}

bool SwarmNodeDefault::seeder() const
{
    return m_role.seeder();
}

bool SwarmNodeDefault::evaluator() const
{
    return m_role.evaluator();
}

int SwarmNodeDefault::slots() const
{
    return m_role.slots();
}

} // namespace modelnet
