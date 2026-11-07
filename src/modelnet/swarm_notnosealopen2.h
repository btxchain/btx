// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSEALOPEN2_H
#define BTX_MODELNET_SWARM_NOTNOSEALOPEN2_H

#include <string>

namespace modelnet {

/**
 * A local note about one piece. piece_id names the piece. sealed marks a
 * sealed piece. want_open asks this note to open it.
 *
 * A sealed piece opens nothing. opened stays false on every path.
 */
struct SwarmNotNoSealOpen2 {
    std::string piece_id;
    bool sealed{false};
    bool want_open{false};
};

/**
 * Outcome of noting a piece without opening it. opened stays false on every
 * path. A sealed piece opens nothing.
 */
struct SwarmNotNoSealOpen2Result {
    std::string code;
    bool opened{false};
};

/**
 * Note a piece without opening it. Order, first match wins: an empty
 * piece_id is PIECE. sealed is NOT_OPENED even when want_open is false.
 * want_open is HELD. Otherwise the note is NOTED and err is cleared. opened
 * stays false on every path. A sealed piece opens nothing.
 */
SwarmNotNoSealOpen2Result SwarmNoteNotNoSealOpen2(const SwarmNotNoSealOpen2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSEALOPEN2_H
