// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTMOONABS_H
#define BTX_MODELNET_SWARM_NOTMOONABS_H

#include <string>

namespace modelnet {

/**
 * A local note about one adapter. want_move asks this note to move bytes.
 *
 * Missing Mooncake moves no bytes. moved and bytes_moved stay false on
 * every path.
 */
struct SwarmNotMoonAbs {
    std::string adapter_id;
    bool want_move{false};
};

/**
 * Outcome of noting an adapter. moved and bytes_moved stay false on every
 * path. Missing Mooncake moves no bytes.
 */
struct SwarmNotMoonAbsResult {
    std::string code;
    bool moved{false};
    bool bytes_moved{false};
};

/**
 * Note an adapter without moving bytes.
 * Order, first match wins: an empty adapter_id is ADAPTER. want_move is
 * ENGINE_ABSENT. Otherwise the note is NOTED and err is clear.
 * moved and bytes_moved stay false on every path.
 * Missing Mooncake moves no bytes.
 */
SwarmNotMoonAbsResult SwarmNoteNotMoonAbs(const SwarmNotMoonAbs& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTMOONABS_H
