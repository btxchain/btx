// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CURSORFENCE_CODES_H
#define BITCOIN_MODELNET_SWARM_CURSORFENCE_CODES_H

namespace modelnet {

/** next is below 0. The cursor stays. */
inline constexpr char kSwarmCursorFenceRange[] = "RANGE";

/** next is at or below the cursor. The cursor stays. */
inline constexpr char kSwarmCursorFenceStale[] = "STALE";

/** next jumps past cursor + 1, or Commit names a step other than the cursor. Nothing moves and nothing is stored. */
inline constexpr char kSwarmCursorFenceGap[] = "GAP";

/** Commit hash is empty. Nothing is stored. */
inline constexpr char kSwarmCursorFenceHash[] = "HASH";

/** The same hash is committed again for the cursor step. The stored hash stays. */
inline constexpr char kSwarmCursorFenceReplay[] = "REPLAY";

/** A different hash is committed for a step that already has one. The first hash stays. */
inline constexpr char kSwarmCursorFenceConflict[] = "CONFLICT";

/** Mine is refused. blocks() stays 0. */
inline constexpr char kSwarmCursorFenceHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CURSORFENCE_CODES_H
