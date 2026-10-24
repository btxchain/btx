// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOABSENT_H
#define BTX_MODELNET_SWARM_NOTNOABSENT_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. present says the engine is here.
 * want_move asks this note to move bytes.
 *
 * A missing engine moves no bytes.
 * bytes_moved and transferred stay false on every path.
 */
struct SwarmNotNoAbsent {
    std::string engine_id;
    bool present{false};
    bool want_move{false};
};

/**
 * Outcome of noting an engine. bytes_moved and transferred stay false
 * on every path: a missing engine moves no bytes.
 */
struct SwarmNotNoAbsentResult {
    std::string code;
    bool bytes_moved{false};
    bool transferred{false};
};

/**
 * Note an engine without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE. present false
 * is ENGINE_ABSENT even when want_move is false. want_move is
 * ENGINE_ABSENT. Otherwise the note is NOTED and err is cleared.
 * bytes_moved and transferred stay false on every path. A missing
 * engine moves no bytes.
 */
SwarmNotNoAbsentResult SwarmNoteNotNoAbsent(const SwarmNotNoAbsent& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOABSENT_H
