// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEDUP_QUIET_H
#define BITCOIN_MODELNET_SWARM_DEDUP_QUIET_H

#include <cstdint>

namespace modelnet {

/**
 * Fixed status for the piece dedup book.
 * bytes_moved() stays 0. launched() stays false. gpu() stays false.
 * There is no setter, and no method reports a byte transfer.
 */
class SwarmPieceDedupQuiet {
public:
    std::int64_t bytes_moved() const;
    bool launched() const;
    bool gpu() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEDUP_QUIET_H
