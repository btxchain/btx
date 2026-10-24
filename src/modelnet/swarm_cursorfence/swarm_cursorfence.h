// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_H

#include <modelnet/swarm_cursorfence/cursor.h>
#include <modelnet/swarm_cursorfence/ledger.h>
#include <modelnet/swarm_cursorfence/quiet.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Cursor-advance plane.
 * The cursor starts at 0. It advances only by exactly 1.
 * This plane does not mine or broadcast.
 *
 * Advance: next below 0 is RANGE and the cursor stays. next at or below
 * the cursor is STALE and the cursor stays. next above cursor + 1 is GAP
 * and the cursor stays. next equal to cursor + 1 sets the cursor to next
 * and returns true.
 *
 * Commit: an empty hash is HASH and stores nothing. step must equal the
 * current cursor. A different step is GAP and stores nothing. The first
 * hash for that step wins. The same hash again is REPLAY. A different
 * hash is CONFLICT and keeps the first.
 *
 * bytes_moved() is 0. mined() is false. Mine() returns HELD and blocks()
 * stays 0.
 */
class SwarmCursorFence {
public:
    bool Advance(int64_t next, std::string& err);
    bool Commit(int64_t step, const std::string& hash, std::string& err);
    bool Mine(std::string& err);

    int64_t cursor() const;
    bool committed(int64_t step) const;
    std::string hash_at(int64_t step) const;
    int64_t bytes_moved() const;
    bool mined() const;
    int64_t blocks() const;

private:
    SwarmCursorFenceCursor m_cursor;
    SwarmCursorFenceLedger m_ledger;
    SwarmCursorFenceQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_H
