// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOCKSPAN_GATE_H
#define BITCOIN_MODELNET_SWARM_CLOCKSPAN_GATE_H

#include <modelnet/swarm_clockspan/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Refusal code for a Note that must not store, or empty when 90 may be stored.
 * seconds below 1 is RANGE. Any other positive seconds that is not 90 is
 * SPACING. A 90 already stored is REPLAY. RANGE and SPACING are decided
 * before REPLAY. This function does not modify the book.
 */
std::string SwarmClockSpanRefusal(const SwarmClockSpanBook& book, int64_t seconds);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOCKSPAN_GATE_H
