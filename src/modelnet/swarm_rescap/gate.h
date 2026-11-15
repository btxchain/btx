// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RESCAP_GATE_H
#define BITCOIN_MODELNET_SWARM_RESCAP_GATE_H

#include <modelnet/swarm_rescap/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * What Raise should do with threads.
 * code is CAP, CAPPED, REPLAY, or empty when the count may be stored.
 * store is true only for a new count from 1 through 64.
 * Storing the count does not raise it.
 * This function does not modify the book.
 */
struct SwarmResCapDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Raise.
 * threads below 1 is CAP and is not stored.
 * threads above 64 is CAPPED and is not stored.
 * A count already stored is REPLAY. The first count stays.
 * Any other count from 1 through 64 may be stored. The caller then
 * returns CAPPED. CAP is decided before the over-cap CAPPED.
 * That CAPPED is decided before REPLAY. REPLAY is decided before
 * the stored CAPPED.
 */
SwarmResCapDecision SwarmResCapDecide(const SwarmResCapBook& book, int64_t threads);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RESCAP_GATE_H
