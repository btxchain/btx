// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SETTLEBUILD_FLAGS_H
#define BITCOIN_MODELNET_SWARM_SETTLEBUILD_FLAGS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Frozen inspectors for an in-memory script plane.
 * The object has no fields. There is no method that changes these values.
 * qualified stays false. broadcast stays false. launched stays false.
 * gpu stays false. atoms_moved stays 0. automatic_spend stays "0".
 * secp_penalty stays false.
 */
class SwarmSettleBuildFlags {
public:
    bool qualified() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool secp_penalty() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SETTLEBUILD_FLAGS_H
