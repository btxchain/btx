// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEALED_H
#define BTX_MODELNET_SWARM_NOTNOSEALED_H

#include <string>

namespace modelnet {

/**
 * A local note about one piece. piece_id names the piece. sealed marks a
 * sealed piece. want_open asks this note to open it.
 *
 * A sealed piece opens nothing and moves no bytes. opened and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoSealed {
    std::string piece_id;
    bool sealed{false};
    bool want_open{false};
};

/**
 * Outcome of noting a piece without opening it. opened and bytes_moved stay
 * false on every path. A sealed piece opens nothing and moves no bytes.
 */
struct SwarmNotNoSealedResult {
    std::string code;
    bool opened{false};
    bool bytes_moved{false};
};

/**
 * Note a piece without opening it and without moving bytes. Order, first
 * match wins: an empty piece_id is PIECE. sealed is REALM_SEALED even when
 * want_open is false. want_open is HELD. Otherwise the note is NOTED and
 * err is clear. opened and bytes_moved stay false on every path. A sealed
 * piece opens nothing and moves no bytes.
 */
SwarmNotNoSealedResult SwarmNoteNotNoSealed(const SwarmNotNoSealed& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEALED_H
