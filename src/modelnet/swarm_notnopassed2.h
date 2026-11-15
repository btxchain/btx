// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPASSED2_H
#define BTX_MODELNET_SWARM_NOTNOPASSED2_H

#include <string>

namespace modelnet {

/**
 * A local note about one stage. want_pass asks this note to treat a
 * unit note as a passed flagship stage.
 *
 * A unit note does not pass a flagship stage, so passed stays false
 * on every path.
 */
struct SwarmNotNoPassed2 {
    std::string stage_id;
    bool want_pass{false};
};

/**
 * Outcome of noting a stage. passed stays false on every path:
 * a unit note does not pass a flagship stage.
 */
struct SwarmNotNoPassed2Result {
    std::string code;
    bool passed{false};
};

/**
 * Note a stage without passing a flagship stage.
 * Order, first match wins: an empty stage_id is STAGE. want_pass is
 * HELD. Otherwise the note is NOTED and err is clear.
 * passed stays false on every path. A unit note does not pass a
 * flagship stage.
 */
SwarmNotNoPassed2Result SwarmNoteNotNoPassed2(const SwarmNotNoPassed2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPASSED2_H
