// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORM_TYPES_H
#define BITCOIN_MODELNET_SWARM_FORM_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Node id of the in-process observer. Not a hostname. */
inline constexpr char kLocalNodeId[] = "local";

/** Family this plane admits against. Discovery does not look one up on the network. */
inline constexpr char kFormationFamilyId[] = "btx-modelnet";

/** Spend authority stored on every formation record. This plane never spends. */
inline constexpr char kAutomaticSpend[] = "0";

/** Hard cap recorded for the local evaluator. The plane does not start those threads. */
inline constexpr int kCpuThreadCap = 64;

inline constexpr char kMembershipFile[] = "formation-membership.json";
inline constexpr char kElectionFile[] = "formation-election.json";

/**
 * Local membership plus the ids already admitted.
 * Roles are seeder and evaluator. Training, private prompts, and spend stay off.
 * No field on this record is a hostname, an address, or a DNS seed.
 */
struct SwarmFormMember {
    std::string node_id;
    bool seeder{false};
    bool evaluator{false};
    bool modelnet_on{false};
    bool training{false};
    bool private_prompts{false};
    std::string automatic_spend{kAutomaticSpend};
    int64_t vram_mib{0};
    int cpu_thread_cap{0};
    std::string family_id;
    std::vector<std::string> admitted;
};

/** The membership a first Form writes for this process. */
inline SwarmFormMember LocalFormationMember()
{
    SwarmFormMember member;
    member.node_id = kLocalNodeId;
    member.seeder = true;
    member.evaluator = true;
    member.modelnet_on = true;
    member.training = false;
    member.private_prompts = false;
    member.automatic_spend = kAutomaticSpend;
    member.vram_mib = 0;
    member.cpu_thread_cap = kCpuThreadCap;
    member.family_id = kFormationFamilyId;
    member.admitted.push_back(kLocalNodeId);
    return member;
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORM_TYPES_H
