// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_FLOOR_H
#define BITCOIN_MODELNET_SWARM_GENERATION_FLOOR_H

#include <modelnet/swarm_generation/codes.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Status this plane cannot change.
 * Nothing is launched, nothing uses a GPU, and no bytes, atoms, or
 * automatic spend move. Broadcast, realm promotion, and exact-replay
 * admission stay closed. running() stays false because no trainer starts.
 */
class SwarmGenerationFloor {
public:
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;
    int64_t atoms_moved() const;
    const std::string& automatic_spend() const;
    bool broadcast() const;
    bool realm_promoted() const;
    bool exact_replay_admitted() const;
    bool running() const;

private:
    std::string m_automatic_spend{kSwarmGenerationAutomaticSpend};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_FLOOR_H
