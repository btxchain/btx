// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_FLAGS_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_FLAGS_H

#include <cstdint>

namespace modelnet {

/**
 * Frozen inspectors for the parentage book.
 * The object has no fields. There is no method that changes these values.
 * trusted stays false. realm_promoted stays false. exact_replay_admitted stays false.
 * launched stays false. gpu stays false. bytes_moved stays 0.
 */
class SwarmParentageFlags {
public:
    bool trusted() const;
    bool realm_promoted() const;
    bool exact_replay_admitted() const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_FLAGS_H
