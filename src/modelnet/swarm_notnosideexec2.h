// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSIDEEXEC2_H
#define BTX_MODELNET_SWARM_NOTNOSIDEEXEC2_H

#include <string>

namespace modelnet {

/**
 * A local note about one name. want_exec asks this note to exec a sidecar.
 *
 * btxd does not exec a sidecar. executed stays false on every path.
 */
struct SwarmNotNoSideExec2 {
    std::string name_id;
    bool want_exec{false};
};

/**
 * Outcome of noting a name. executed stays false on every path.
 */
struct SwarmNotNoSideExec2Result {
    std::string code;
    bool executed{false};
};

/**
 * Note a name without execing a sidecar.
 * Order, first match wins: an empty name_id is NAME. want_exec is HELD.
 * Otherwise the note is NOTED and err is cleared. executed stays false
 * on every path. btxd does not exec a sidecar.
 */
SwarmNotNoSideExec2Result SwarmNoteNotNoSideExec2(const SwarmNotNoSideExec2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSIDEEXEC2_H
