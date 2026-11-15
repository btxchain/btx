// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTRAJ2_H
#define BTX_MODELNET_SWARM_NOTNOTRAJ2_H

#include <string>

namespace modelnet {

/**
 * A local note about one trajectory. stored marks that the trajectory
 * is stored. want_learn asks this note to learn from it.
 *
 * An unstored trajectory learns nothing, so learned and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoTraj2 {
    std::string traj_id;
    bool stored{false};
    bool want_learn{false};
};

/**
 * Outcome of noting a trajectory. learned and bytes_moved stay false
 * on every path. An unstored trajectory learns nothing.
 */
struct SwarmNotNoTraj2Result {
    std::string code;
    bool learned{false};
    bool bytes_moved{false};
};

/**
 * Note a trajectory without learning.
 * Order, first match wins: an empty traj_id is TRAJ.
 * stored false is NOT_LEARNED even when want_learn is false.
 * want_learn is HELD. Otherwise the note is NOTED and err is cleared.
 * learned and bytes_moved stay false on every path. An unstored
 * trajectory learns nothing.
 */
SwarmNotNoTraj2Result SwarmNoteNotNoTraj2(const SwarmNotNoTraj2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTRAJ2_H
