// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG05_H
#define BTX_MODELNET_SWARM_FLAG05_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 5 generate experience: an authorized public or
 * synthetic trajectory. agent_id and task_id name the note.
 * authorized and synthetic_or_public must both be set before a
 * trajectory may be noted. want_record asks this note to record the
 * trajectory. want_pass asks this note to treat the trajectory as
 * passed.
 *
 * This note does not record a trajectory. recorded, passed, and
 * bytes_moved stay false on every path.
 */
struct SwarmFlag05 {
    std::string agent_id;
    std::string task_id;
    bool authorized{false};
    bool synthetic_or_public{false};
    bool want_record{false};
    bool want_pass{false};
};

/**
 * Outcome of flagship stage 5 generate experience. recorded, passed,
 * and bytes_moved stay false on every path.
 */
struct SwarmFlag05Result {
    std::string code;
    bool recorded{false};
    bool passed{false};
    bool bytes_moved{false};
};

/**
 * Note flagship stage 5 generate experience. An authorized public or
 * synthetic trajectory is still only a note.
 * Order, first match wins: an empty agent_id or task_id is AGENT.
 * authorized false or synthetic_or_public false is UNAUTHORIZED, even
 * when want_record is set. want_record is NOT_RECORDED. want_pass is
 * UNQUALIFIED. Otherwise the note is NOTED and err is cleared.
 * recorded, passed, and bytes_moved stay false on every path.
 */
SwarmFlag05Result SwarmStageExperience(const SwarmFlag05& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG05_H
