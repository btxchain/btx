// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_SPAN_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_SPAN_H

#include <cstdint>

namespace modelnet {

/** How next sits relative to the cursor. */
enum class SwarmCursorFenceMove {
    Exact,
    Range,
    Stale,
    Gap,
};

/**
 * Classify next against cursor.
 * next below 0 is Range.
 * next at or below cursor is Stale.
 * next equal to cursor + 1 is Exact.
 * next above cursor + 1 is Gap.
 * The sum uses a wide integer so a cursor at the top of int64_t is Gap
 * for every int64_t next that is not Stale or Range.
 */
SwarmCursorFenceMove SwarmCursorFenceClassify(int64_t cursor, int64_t next);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_SPAN_H
