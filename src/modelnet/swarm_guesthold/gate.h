// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_GATE_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_GATE_H

#include <modelnet/swarm_guesthold/book.h>

#include <string>

namespace modelnet {

/**
 * What Check should do with name.
 * code is GUEST, REPLAY, or empty when the name may be stored.
 * store is true only for a new non-empty name.
 * Storing the name does not pass it and does not log it in.
 * This function does not modify the book.
 */
struct SwarmGuestHoldDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Check.
 * An empty name is GUEST and is not stored.
 * A name already stored is REPLAY. The first check stays.
 * Any other name may be stored. The caller then returns NOT_PASSED.
 * GUEST is decided before REPLAY. REPLAY is decided before NOT_PASSED.
 */
SwarmGuestHoldDecision SwarmGuestHoldDecide(const SwarmGuestHoldBook& book, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_GATE_H
