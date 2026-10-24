// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTRUNC_H
#define BTX_MODELNET_SWARM_NOTNOTRUNC_H

#include <string>

namespace modelnet {

/**
 * A local note about one cache piece. want_move asks this note to move it.
 * truncated marks that the piece is truncated.
 *
 * A truncated cache piece moves no bytes, so moved stays false and
 * bytes_moved stays false on every path.
 */
struct SwarmNotNoTrunc {
    std::string piece_id;
    bool truncated{false};
    bool want_move{false};
};

/**
 * Outcome of noting a cache piece. moved and bytes_moved stay false on
 * every path: a truncated cache piece moves no bytes.
 */
struct SwarmNotNoTruncResult {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note a cache piece without moving it. Order, first match wins: an empty
 * piece_id is PIECE. truncated is NOT_MOVED even when want_move is false.
 * want_move is HELD. Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path. A truncated cache piece
 * moves no bytes.
 */
SwarmNotNoTruncResult SwarmNoteNotNoTrunc(const SwarmNotNoTrunc& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTRUNC_H
