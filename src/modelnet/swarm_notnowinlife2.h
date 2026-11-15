// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWINLIFE2_H
#define BTX_MODELNET_SWARM_NOTNOWINLIFE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one check. want_pass asks this note to treat a
 * unit note as a Windows lifecycle pass.
 *
 * A unit note does not pass a Windows lifecycle, so passed stays false
 * on every path.
 */
struct SwarmNotNoWinLife2 {
    std::string check_id;
    bool want_pass{false};
};

/**
 * Outcome of noting a check. passed stays false on every path:
 * a unit note does not pass a Windows lifecycle.
 */
struct SwarmNotNoWinLife2Result {
    std::string code;
    bool passed{false};
};

/**
 * Note a check without passing a Windows lifecycle.
 * Order, first match wins: an empty check_id is CHECK. want_pass is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * passed stays false on every path. A unit note does not pass a Windows
 * lifecycle.
 */
SwarmNotNoWinLife2Result SwarmNoteNotNoWinLife2(const SwarmNotNoWinLife2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWINLIFE2_H
