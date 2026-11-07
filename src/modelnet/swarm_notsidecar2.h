// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSIDECAR2_H
#define BTX_MODELNET_SWARM_NOTSIDECAR2_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_external asks this note to place
 * the control plane outside btxd.
 *
 * The control plane stays inside btxd. external and launched stay false
 * on every path.
 */
struct SwarmNotSidecar2 {
    std::string node_id;
    bool want_external{false};
};

/**
 * Outcome of noting a node. external and launched stay false on every
 * path: the control plane stays inside btxd.
 */
struct SwarmNotSidecar2Result {
    std::string code;
    bool external{false};
    bool launched{false};
};

/**
 * Note a node while the control plane stays inside btxd.
 * Order, first match wins: an empty node_id is NODE.
 * want_external is INSIDE. Otherwise the note is NOTED and err is clear.
 * external and launched stay false on every path.
 */
SwarmNotSidecar2Result SwarmNoteNotSidecar2(const SwarmNotSidecar2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSIDECAR2_H
