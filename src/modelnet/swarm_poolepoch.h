// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_POOLEPOCH_H
#define BTX_MODELNET_SWARM_POOLEPOCH_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about a pool policy epoch. pool_id names the pool being
 * noted. stored_epoch is the epoch already on record. next_epoch is the
 * epoch offered next. want_move_obligations asks to move obligations that
 * belong to the stored epoch.
 *
 * Raising the policy epoch does not move old obligations. This is a local
 * note. Nothing is signed and nothing is broadcast. No hostnames or IPs
 * are used.
 */
struct SwarmPoolEpoch {
    std::string pool_id;
    int64_t stored_epoch{0};
    int64_t next_epoch{0};
    bool want_move_obligations{false};
};

/**
 * A local pool-epoch note. moved stays false on every path: a higher
 * epoch still does not move old obligations.
 */
struct SwarmPoolEpochResult {
    bool moved{false};
    std::string code;
};

/**
 * Order, first match wins: an empty pool_id, a stored_epoch below 1, or
 * a next_epoch below 1 is EPOCH. A next_epoch at or below stored_epoch is
 * STALE, including when want_move_obligations is true. want_move_obligations
 * is IMMUTABLE. Otherwise the note is NOTED and err is clear.
 * moved stays false on every path. Raising the policy epoch does not move
 * old obligations. Nothing is signed and nothing is broadcast. No
 * hostnames or IPs are used.
 */
SwarmPoolEpochResult SwarmNotePoolEpoch(const SwarmPoolEpoch& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_POOLEPOCH_H
