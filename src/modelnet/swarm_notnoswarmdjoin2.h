// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSWARMDJOIN2_H
#define BTX_MODELNET_SWARM_NOTNOSWARMDJOIN2_H

#include <string>

namespace modelnet {

/**
 * A local note about one name on the join path. sidecar records whether
 * the name is a sidecar. want_launch asks this note to launch a process.
 *
 * A sidecar name on the join path launches nothing. The control plane
 * stays inside btxd. launched stays false on every path.
 */
struct SwarmNotNoSwarmdJoin2 {
    std::string name_id;
    bool sidecar{false};
    bool want_launch{false};
};

/**
 * Outcome of noting a join. launched stays false on every path: a
 * sidecar name on the join path launches nothing, and the control plane
 * stays inside btxd.
 */
struct SwarmNotNoSwarmdJoin2Result {
    std::string code;
    bool launched{false};
};

/**
 * Note a join without launching a sidecar process.
 * Order, first match wins: an empty name_id is NAME. sidecar true is
 * NOT_LAUNCHED, even when want_launch is false. want_launch is HELD.
 * Otherwise the note is NOTED and err is cleared. launched stays false
 * on every path. A sidecar name on the join path launches nothing. The
 * control plane stays inside btxd.
 */
SwarmNotNoSwarmdJoin2Result SwarmNoteNotNoSwarmdJoin2(const SwarmNotNoSwarmdJoin2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSWARMDJOIN2_H
