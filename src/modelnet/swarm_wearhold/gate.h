// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WEARHOLD_GATE_H
#define BITCOIN_MODELNET_SWARM_WEARHOLD_GATE_H

#include <modelnet/swarm_wearhold/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Refusal code for a Measure that must not store, or empty when joules
 * may be stored. joules below 1 is MEASURE. A count at least 1 that is
 * already stored is REPLAY. MEASURE is decided before REPLAY.
 * This function does not modify the book.
 */
std::string SwarmWearHoldRefusal(const SwarmWearHoldBook& book, int64_t joules);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WEARHOLD_GATE_H
