// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWINDOWS2_H
#define BTX_MODELNET_SWARM_NOTNOWINDOWS2_H

#include <string>

namespace modelnet {

/**
 * A local note about one check. want_pass asks this note to treat a
 * unit note as a Windows pass.
 *
 * A unit note does not pass Windows, so passed stays false on every path.
 */
struct SwarmNotNoWindows2 {
    std::string check_id;
    bool want_pass{false};
};

/**
 * Outcome of noting a check. passed stays false on every path:
 * a unit note does not pass Windows.
 */
struct SwarmNotNoWindows2Result {
    std::string code;
    bool passed{false};
};

/**
 * Note a check without passing Windows.
 * Order, first match wins: an empty check_id is CHECK. want_pass is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * passed stays false on every path. A unit note does not pass Windows.
 */
SwarmNotNoWindows2Result SwarmNoteNotNoWindows2(const SwarmNotNoWindows2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWINDOWS2_H
