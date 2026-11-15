// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTRAJECTORY_H
#define BTX_MODELNET_SWARM_NOTNOTRAJECTORY_H

#include <string>

namespace modelnet {

/**
 * A local note about one trajectory. unstored marks that the trajectory
 * is not stored. want_learn asks this note to learn from it.
 *
 * An unstored trajectory learns nothing and trains nothing, so learned
 * stays false and trained stays false on every path.
 */
struct SwarmNotNoTrajectory {
    std::string traj_id;
    bool unstored{false};
    bool want_learn{false};
};

/**
 * Outcome of noting a trajectory. learned stays false and trained stays
 * false on every path. An unstored trajectory learns nothing and trains
 * nothing.
 */
struct SwarmNotNoTrajectoryResult {
    std::string code;
    bool learned{false};
    bool trained{false};
};

/**
 * Note a trajectory without learning or training.
 * Order, first match wins: an empty traj_id is TRAJ.
 * unstored is NOT_STORED even when want_learn is false.
 * want_learn is HELD. Otherwise the note is NOTED and err is cleared.
 * learned stays false and trained stays false on every path. An
 * unstored trajectory learns nothing and trains nothing.
 */
SwarmNotNoTrajectoryResult SwarmNoteNotNoTrajectory(const SwarmNotNoTrajectory& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTRAJECTORY_H
