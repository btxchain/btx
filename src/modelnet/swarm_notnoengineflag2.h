// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOENGINEFLAG2_H
#define BTX_MODELNET_SWARM_NOTNOENGINEFLAG2_H

#include <string>

namespace modelnet {

/**
 * A local note about one caller engine flag. engine_flag says the caller
 * set an engine flag. want_move asks this note to move bytes.
 *
 * A caller engine flag is not a KV transfer.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoEngineFlag2 {
    std::string transfer_id;
    bool engine_flag{false};
    bool want_move{false};
};

/**
 * Outcome of noting an engine flag. moved and bytes_moved stay false on
 * every path: a caller engine flag is not a KV transfer and moves no bytes.
 */
struct SwarmNotNoEngineFlag2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note an engine flag without moving bytes.
 * Order, first match wins: an empty transfer_id is TRANSFER. engine_flag
 * true is NOT_TRANSFER even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path. A caller engine flag
 * is not a KV transfer.
 */
SwarmNotNoEngineFlag2Result SwarmNoteNotNoEngineFlag2(const SwarmNotNoEngineFlag2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOENGINEFLAG2_H
