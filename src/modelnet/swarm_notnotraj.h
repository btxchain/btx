// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTRAJ_H
#define BTX_MODELNET_SWARM_NOTNOTRAJ_H

#include <string>

namespace modelnet {

/**
 * A local note about one stored trajectory. want_train asks this note
 * to start a training run from that trajectory.
 *
 * A stored trajectory is not a training run. trained and bytes_moved
 * stay false on every path.
 */
struct SwarmNotNoTraj {
    std::string traj_id;
    bool want_train{false};
};

/**
 * Outcome of noting a trajectory. trained and bytes_moved stay false
 * on every path. A stored trajectory is not a training run.
 */
struct SwarmNotNoTrajResult {
    std::string code;
    bool trained{false};
    bool bytes_moved{false};
};

/**
 * Note a stored trajectory without training.
 * Order, first match wins: an empty traj_id is TRAJ.
 * want_train is NOT_TRAIN. Otherwise the note is NOTED and err
 * is clear. trained and bytes_moved stay false on every path.
 * A stored trajectory is not a training run.
 */
SwarmNotNoTrajResult SwarmNoteNotNoTraj(const SwarmNotNoTraj& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTRAJ_H
