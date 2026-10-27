// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTRAJECTORY_H
#define BTX_MODELNET_SWARM_NOTTRAJECTORY_H

#include <string>

namespace modelnet {

/**
 * A local note that an agent might record an authorized public or synthetic
 * trajectory. want_record asks this note to treat a trajectory as recorded.
 *
 * No authorized public or synthetic trajectory has been generated from a
 * running agent, so recorded stays false on every path.
 */
struct SwarmNotTrajectory {
    std::string agent_id;
    bool want_record{false};
};

/**
 * Outcome of noting that no authorized public or synthetic trajectory has
 * been generated from a running agent. recorded stays false on every path.
 */
struct SwarmNotTrajectoryResult {
    std::string code;
    bool recorded{false};
};

/**
 * Note that no authorized public or synthetic trajectory has been generated
 * from a running agent. Order, first match wins: an empty agent_id is AGENT.
 * want_record is NOT_RECORDED. Otherwise the note is NOTED and err is clear.
 * recorded stays false on every path.
 */
SwarmNotTrajectoryResult SwarmNoteNotTrajectory(const SwarmNotTrajectory& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTRAJECTORY_H
