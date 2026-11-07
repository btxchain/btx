// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGUESTAGENT2_H
#define BTX_MODELNET_SWARM_NOTNOGUESTAGENT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one check. no_agent records that a guest agent is
 * missing. want_pass asks this note to mark Windows passed.
 *
 * A missing guest agent does not pass Windows. passed stays false on
 * every path.
 */
struct SwarmNotNoGuestAgent2 {
    std::string check_id;
    bool no_agent{false};
    bool want_pass{false};
};

/**
 * Outcome of noting a check. passed stays false on every path.
 * A missing guest agent does not pass Windows.
 */
struct SwarmNotNoGuestAgent2Result {
    std::string code;
    bool passed{false};
};

/**
 * Note a check without marking Windows passed.
 * Order, first match wins: an empty check_id is CHECK. no_agent is
 * NOT_PASSED even when want_pass is false. want_pass is HELD.
 * Otherwise the note is NOTED and err is clear.
 * passed stays false on every path.
 * A missing guest agent does not pass Windows.
 */
SwarmNotNoGuestAgent2Result SwarmNoteNotNoGuestAgent2(const SwarmNotNoGuestAgent2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGUESTAGENT2_H
