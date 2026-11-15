// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_REFUND_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_REFUND_H

#include <modelnet/swarm_watchhold/cursor.h>
#include <modelnet/swarm_watchhold/note.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Hold a refund, or refuse it.
 * refund_height below height + 160 is MARGIN and stores nothing.
 * Before any sequence has been observed the code is SEQUENCE and nothing
 * is stored. Once a sequence has been observed the code is HELD.
 * HELD remembers the heights locally and does not broadcast.
 * This function takes no secret and cannot release one.
 */
bool SwarmWatchHoldRefund(const SwarmWatchHoldCursor& cursor, SwarmWatchHoldNote& note, int64_t height, int64_t refund_height, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_REFUND_H
