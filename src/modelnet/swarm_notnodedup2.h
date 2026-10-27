// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNODEDUP2_H
#define BTX_MODELNET_SWARM_NOTNODEDUP2_H

#include <string>

namespace modelnet {

/**
 * A local note about one piece. other_realm marks the piece as
 * belonging to another realm. want_move asks this note to move it.
 *
 * Cross-realm dedup moves nothing.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoDedup2 {
    std::string piece_id;
    bool other_realm{false};
    bool want_move{false};
};

/**
 * Outcome of noting a piece. moved and bytes_moved stay false on every
 * path. Cross-realm dedup moves nothing.
 */
struct SwarmNotNoDedup2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note a piece without moving it or its bytes. Order, first match
 * wins: an empty piece_id is PIECE. other_realm is NOT_MOVED even when
 * want_move is false. want_move is HELD. Otherwise the note is NOTED
 * and err is cleared. moved and bytes_moved stay false on every path.
 * Cross-realm dedup moves nothing.
 */
SwarmNotNoDedup2Result SwarmNoteNotNoDedup2(const SwarmNotNoDedup2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNODEDUP2_H
