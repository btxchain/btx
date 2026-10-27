// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOKVMOVE2_H
#define BTX_MODELNET_SWARM_NOTNOKVMOVE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one KV placement. want_move asks this note to move
 * the placement. A KV placement note moves no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoKvMove2 {
    std::string transfer_id;
    bool want_move{false};
};

/**
 * Outcome of noting a KV placement. moved and bytes_moved stay false on
 * every path. A KV placement note moves no bytes.
 */
struct SwarmNotNoKvMove2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note a KV placement without moving bytes.
 * Order, first match wins: an empty transfer_id is TRANSFER.
 * want_move is HELD. Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path.
 * A KV placement note moves no bytes.
 */
SwarmNotNoKvMove2Result SwarmNoteNotNoKvMove2(const SwarmNotNoKvMove2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOKVMOVE2_H
