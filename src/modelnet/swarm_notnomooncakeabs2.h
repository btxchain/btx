// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMOONCAKEABS2_H
#define BTX_MODELNET_SWARM_NOTNOMOONCAKEABS2_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. mooncake_absent says the Mooncake adapter
 * is missing. want_move asks this note to move bytes.
 *
 * A missing Mooncake adapter moves no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoMooncakeAbs2 {
    std::string engine_id;
    bool mooncake_absent{false};
    bool want_move{false};
};

/**
 * Outcome of noting an engine. moved and bytes_moved stay false on
 * every path: a missing Mooncake adapter moves no bytes.
 */
struct SwarmNotNoMooncakeAbs2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note an engine without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE. mooncake_absent
 * true is ENGINE_ABSENT even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path. A missing Mooncake adapter
 * moves no bytes.
 */
SwarmNotNoMooncakeAbs2Result SwarmNoteNotNoMooncakeAbs2(const SwarmNotNoMooncakeAbs2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMOONCAKEABS2_H
