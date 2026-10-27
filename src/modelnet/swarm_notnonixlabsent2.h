// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONIXLABSENT2_H
#define BTX_MODELNET_SWARM_NOTNONIXLABSENT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. nixl_absent says the NIXL adapter is missing.
 * want_move asks this note to move bytes.
 *
 * A missing NIXL adapter moves no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoNixlAbsent2 {
    std::string engine_id;
    bool nixl_absent{false};
    bool want_move{false};
};

/**
 * Outcome of noting an engine. moved and bytes_moved stay false on
 * every path: a missing NIXL adapter moves no bytes.
 */
struct SwarmNotNoNixlAbsent2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note an engine without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE. nixl_absent true
 * is ENGINE_ABSENT even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path. A missing NIXL adapter
 * moves no bytes.
 */
SwarmNotNoNixlAbsent2Result SwarmNoteNotNoNixlAbsent2(const SwarmNotNoNixlAbsent2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONIXLABSENT2_H
