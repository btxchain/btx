// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_QUIET_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_QUIET_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * What this evaluation plane is not allowed to do.
 * launched() stays false. gpu() stays false. bytes_moved() stays 0.
 * atoms_moved() stays 0. automatic_spend() stays "0". broadcast() stays
 * false. realm_promoted() stays false. exact_replay_admitted() stays
 * false. money() stays false. There is no method that sets any of them.
 */
class SwarmEvaluationQuiet {
public:
    bool launched() const;
    bool gpu() const;
    std::uint64_t bytes_moved() const;
    std::uint64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool broadcast() const;
    bool realm_promoted() const;
    bool exact_replay_admitted() const;
    bool money() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_QUIET_H
