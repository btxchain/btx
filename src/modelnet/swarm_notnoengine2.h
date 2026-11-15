// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOENGINE2_H
#define BTX_MODELNET_SWARM_NOTNOENGINE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. present says the engine is here.
 * want_move asks this note to move bytes.
 *
 * A missing engine moves no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoEngine2 {
    std::string engine_id;
    bool present{false};
    bool want_move{false};
};

/**
 * Outcome of noting an engine. moved and bytes_moved stay false on
 * every path: a missing engine moves no bytes.
 */
struct SwarmNotNoEngine2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note an engine without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE. present false
 * is ENGINE_ABSENT even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path. A missing engine
 * moves no bytes.
 */
SwarmNotNoEngine2Result SwarmNoteNotNoEngine2(const SwarmNotNoEngine2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOENGINE2_H
