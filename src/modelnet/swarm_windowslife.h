// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WINDOWSLIFE_H
#define BTX_MODELNET_SWARM_WINDOWSLIFE_H

#include <string>

namespace modelnet {

/**
 * A local Windows lifecycle record for one node. want_pass asks this
 * note to treat the record as a pass.
 *
 * A missing guest agent does not pass a Windows lifecycle. A pass
 * request is held. passed stays false on every path.
 */
struct SwarmWindowsLife {
    std::string node_id;
    bool guest_agent{false};
    bool want_pass{false};
};

/**
 * Outcome of noting a Windows lifecycle. passed stays false on every
 * path: a missing guest agent does not pass a Windows lifecycle.
 */
struct SwarmWindowsLifeResult {
    std::string code;
    bool passed{false};
};

/**
 * Note a Windows lifecycle without passing it.
 * Order, first match wins: an empty node_id is NODE. A missing guest
 * agent is NOT_PASSED, even when want_pass is false. want_pass is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * passed stays false on every path. A missing guest agent does not pass
 * a Windows lifecycle.
 */
SwarmWindowsLifeResult SwarmNoteWindowsLife(const SwarmWindowsLife& node, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WINDOWSLIFE_H
