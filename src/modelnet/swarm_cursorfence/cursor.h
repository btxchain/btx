// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_CURSOR_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_CURSOR_H

#include <modelnet/swarm_cursorfence/limits.h>

#include <cstdint>

namespace modelnet {

/**
 * The cursor.
 * It starts at 0. Advance stores next only when next is exactly cursor + 1.
 * A range, stale, or gap next is refused and the cursor stays.
 * There is no rewind, no jump, and no method that mines.
 */
class SwarmCursorFenceCursor {
public:
    int64_t cursor() const;

    /**
     * Store next as the cursor.
     * Refuses every next that is not exactly one above the current cursor.
     * On refusal the cursor is unchanged.
     */
    bool Advance(int64_t next);

private:
    int64_t m_cursor{kSwarmCursorFenceOrigin};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_CURSOR_H
