// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CURSORSTEP_H
#define BTX_MODELNET_SWARM_CURSORSTEP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-memory cursor that moves only one step forward.
 * The cursor starts at 0. Advance accepts only the next integer.
 * A next at or behind the cursor is STALE and leaves the cursor where
 * it is, so a stale next does not rewind it. A next more than one ahead
 * is GAP and also leaves the cursor.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmCursorStep {
public:
    /**
     * next <= cursor is STALE and leaves the cursor.
     * next > cursor + 1 is GAP and leaves the cursor.
     * Otherwise the cursor becomes next, err is cleared, and the call
     * returns true.
     */
    bool Advance(uint64_t next, std::string& err);

    /** Current cursor. Starts at 0. */
    uint64_t cursor() const;

private:
    uint64_t m_cursor{0};
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CURSORSTEP_H
