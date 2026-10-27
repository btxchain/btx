// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSIDECARNAME2_H
#define BTX_MODELNET_SWARM_NOTNOSIDECARNAME2_H

#include <string>

namespace modelnet {

/**
 * A local note about one name. sidecar records whether the name is a
 * sidecar. want_launch asks this note to launch a process.
 *
 * A sidecar name does not launch a process. launched stays false on
 * every path.
 */
struct SwarmNotNoSidecarName2 {
    std::string name_id;
    bool sidecar{false};
    bool want_launch{false};
};

/**
 * Outcome of noting a name. launched stays false on every path.
 */
struct SwarmNotNoSidecarName2Result {
    std::string code;
    bool launched{false};
};

/**
 * Note a name without launching a sidecar process.
 * Order, first match wins: an empty name_id is NAME. sidecar true is
 * NOT_LAUNCHED, even when want_launch is false. want_launch is HELD.
 * Otherwise the note is NOTED and err is cleared. launched stays false
 * on every path. A sidecar name does not launch a process.
 */
SwarmNotNoSidecarName2Result SwarmNoteNotNoSidecarName2(const SwarmNotNoSidecarName2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSIDECARNAME2_H
