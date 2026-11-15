// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWIN_H
#define BTX_MODELNET_SWARM_NOTNOWIN_H

#include <string>

namespace modelnet {

/**
 * A local note about one host. want_pass asks this note to treat a
 * Windows claim as a platform pass.
 *
 * A Windows claim is unqualified. This note does not mark a platform
 * passed, so passed and guest_agent stay false on every path.
 */
struct SwarmNotNoWin {
    std::string host_id;
    bool want_pass{false};
};

/**
 * Outcome of noting a host. passed and guest_agent stay false on every
 * path: this note does not mark a platform passed.
 */
struct SwarmNotNoWinResult {
    std::string code;
    bool passed{false};
    bool guest_agent{false};
};

/**
 * Note a host without marking a platform passed.
 * Order, first match wins: an empty host_id is HOST. want_pass is
 * UNQUALIFIED. Otherwise the note is NOTED and err is clear.
 * passed and guest_agent stay false on every path. A Windows claim is
 * unqualified. This note does not mark a platform passed.
 */
SwarmNotNoWinResult SwarmNoteNotNoWin(const SwarmNotNoWin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWIN_H
