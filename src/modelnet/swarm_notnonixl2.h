// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONIXL2_H
#define BTX_MODELNET_SWARM_NOTNONIXL2_H

#include <string>

namespace modelnet {

/**
 * A local note about one adapter. present says the NIXL adapter is here.
 * want_move asks this note to move bytes.
 *
 * A missing NIXL adapter moves no bytes.
 * moved and bytes_moved stay false on every path.
 */
struct SwarmNotNoNixl2 {
    std::string adapter_id;
    bool present{false};
    bool want_move{false};
};

/**
 * Outcome of noting an adapter. moved and bytes_moved stay false on
 * every path: a missing NIXL adapter moves no bytes.
 */
struct SwarmNotNoNixl2Result {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note an adapter without moving bytes.
 * Order, first match wins: an empty adapter_id is ADAPTER. present false
 * is ENGINE_ABSENT even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved and bytes_moved stay false on every path. A missing NIXL adapter
 * moves no bytes.
 */
SwarmNotNoNixl2Result SwarmNoteNotNoNixl2(const SwarmNotNoNixl2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONIXL2_H
