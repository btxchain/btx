// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ROUTEBOOK_FLAGS_H
#define BITCOIN_MODELNET_SWARM_ROUTEBOOK_FLAGS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Frozen inspectors for the route-slack book.
 * The object has no fields. There is no method that changes these values.
 * qualified stays false. secp_penalty stays false. broadcast stays false.
 * launched stays false. gpu stays false. atoms_moved stays 0.
 * automatic_spend stays "0". signed_ok stays false.
 */
class SwarmRouteBookFlags {
public:
    bool qualified() const;
    bool secp_penalty() const;
    bool broadcast() const;
    bool launched() const;
    bool gpu() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool signed_ok() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ROUTEBOOK_FLAGS_H
