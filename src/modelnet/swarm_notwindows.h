// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTWINDOWS_H
#define BTX_MODELNET_SWARM_NOTWINDOWS_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_pass asks this note to treat a
 * Windows guest that has not run a BTX binary as a pass.
 *
 * A Windows guest that has not run a BTX binary is not a pass.
 * passed stays false on every path.
 */
struct SwarmNotWindows {
    std::string node_id;
    bool want_pass{false};
};

/**
 * Outcome of noting a Windows guest. passed stays false on every path:
 * a Windows guest that has not run a BTX binary is not a pass.
 */
struct SwarmNotWindowsResult {
    std::string code;
    bool passed{false};
};

/**
 * Note a Windows guest without treating it as a pass.
 * Order, first match wins: an empty node_id is WINDOWS.
 * want_pass is UNQUALIFIED.
 * Otherwise the note is NOTED and err is clear.
 * passed stays false on every path. A Windows guest that has not run a
 * BTX binary is not a pass.
 */
SwarmNotWindowsResult SwarmNoteNotWindows(const SwarmNotWindows& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTWINDOWS_H
