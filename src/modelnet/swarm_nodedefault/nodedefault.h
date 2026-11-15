// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_H

#include <modelnet/swarm_nodedefault/cpu.h>
#include <modelnet/swarm_nodedefault/gate.h>
#include <modelnet/swarm_nodedefault/privacy.h>
#include <modelnet/swarm_nodedefault/profile.h>
#include <modelnet/swarm_nodedefault/role.h>
#include <modelnet/swarm_nodedefault/seeds.h>
#include <modelnet/swarm_nodedefault/spend.h>
#include <modelnet/swarm_nodedefault/training.h>
#include <modelnet/swarm_nodedefault/vram.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Default node profile. Every field below is readable from construction.
 * This plane does not open a socket, add a DNS seed, spawn a process, or
 * spend.
 *
 * modelnet_on() is true. DisableModelNet() is HELD and leaves it true.
 * launch_profile() is BTX035-LAUNCH-DECODER-2x64. RenameProfile() is HELD
 * and leaves that string.
 * dns_seeds() is empty. AddSeed() is HELD and the list stays empty.
 * training() is false. private_prompts() is false. EnableTraining() and
 * EnablePrivate() are HELD and leave those false.
 * automatic_spend() is "0" until an operator-signed bound of at least 1
 * is recorded. ArmSpend checks, first match: an already armed plane is
 * REPLAY; a research key or scheduler is NOT_SIGNED; operator_signed
 * false is NOT_SIGNED; atoms below 1 is BOUND. A passing arm stores the
 * decimal string and armed() becomes true. atoms_moved() stays 0.
 * cpu_threads() is 64. RaiseThreads() with n above 64 or below 0 is
 * CAPPED and leaves 64. A request in 0..64 leaves 64.
 * vram_mib() is 0. ClaimVram() with n other than 0 is VRAM_ZERO and
 * leaves 0. ClaimVram(0) leaves 0.
 * seeder() and evaluator() are true. slots() is 1.
 */
class SwarmNodeDefault {
public:
    bool modelnet_on() const;
    bool DisableModelNet(std::string& err);

    const std::string& launch_profile() const;
    bool RenameProfile(const std::string& name, std::string& err);

    const std::vector<std::string>& dns_seeds() const;
    bool AddSeed(const std::string& seed, std::string& err);

    bool training() const;
    bool EnableTraining(std::string& err);

    bool private_prompts() const;
    bool EnablePrivate(std::string& err);

    const std::string& automatic_spend() const;
    bool armed() const;
    int64_t atoms_moved() const;
    bool ArmSpend(int64_t atoms, bool operator_signed, bool research_key, bool scheduler, std::string& err);

    int cpu_threads() const;
    bool RaiseThreads(int n, std::string& err);

    int64_t vram_mib() const;
    bool ClaimVram(int64_t n, std::string& err);

    bool seeder() const;
    bool evaluator() const;
    int slots() const;

private:
    SwarmNodeDefaultGate m_gate;
    SwarmNodeDefaultProfile m_profile;
    SwarmNodeDefaultSeeds m_seeds;
    SwarmNodeDefaultTraining m_training;
    SwarmNodeDefaultPrivacy m_privacy;
    SwarmNodeDefaultSpend m_spend;
    SwarmNodeDefaultCpu m_cpu;
    SwarmNodeDefaultVram m_vram;
    SwarmNodeDefaultRole m_role;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_H
