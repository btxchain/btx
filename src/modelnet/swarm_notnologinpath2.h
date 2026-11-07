// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLOGINPATH2_H
#define BTX_MODELNET_SWARM_NOTNOLOGINPATH2_H

#include <string>

namespace modelnet {

/**
 * A unit note opens no Windows login path.
 * want_login asks this note to open one. It does not.
 */
struct SwarmNotNoLoginPath2 {
    std::string check_id;
    bool want_login{false};
};

/**
 * Outcome of a unit note. logged_in stays false on every path.
 * A unit note opens no Windows login path.
 */
struct SwarmNotNoLoginPath2Result {
    std::string code;
    bool logged_in{false};
};

/**
 * Note that no Windows login path is opened.
 * Order, first match wins: an empty check_id is CHECK. want_login is HELD.
 * Otherwise the note is NOTED and err is clear.
 * logged_in stays false on every path.
 * A unit note opens no Windows login path.
 */
SwarmNotNoLoginPath2Result SwarmNoteNotNoLoginPath2(const SwarmNotNoLoginPath2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLOGINPATH2_H
