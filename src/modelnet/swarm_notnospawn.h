// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSPAWN_H
#define BTX_MODELNET_SWARM_NOTNOSPAWN_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_exec asks this note to launch a
 * sidecar. node_id names the node.
 *
 * The control plane stays inside btxd and this note launches no sidecar.
 * launched and external stay false on every path.
 */
struct SwarmNotNoSpawn {
    std::string node_id;
    bool want_exec{false};
};

/**
 * Outcome of noting a node. launched and external stay false on every
 * path: the control plane stays inside btxd and this note launches no
 * sidecar.
 */
struct SwarmNotNoSpawnResult {
    std::string code;
    bool launched{false};
    bool external{false};
};

/**
 * Note a node without launching a sidecar.
 * Order, first match wins: an empty node_id is NODE.
 * want_exec is NOT_LAUNCHED. Otherwise the note is NOTED and err
 * is clear. launched and external stay false on every path. The
 * control plane stays inside btxd and this note launches no sidecar.
 */
SwarmNotNoSpawnResult SwarmNoteNotNoSpawn(const SwarmNotNoSpawn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSPAWN_H
