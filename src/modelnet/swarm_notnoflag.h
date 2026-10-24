// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFLAG_H
#define BTX_MODELNET_SWARM_NOTNOFLAG_H

#include <string>

namespace modelnet {

/**
 * A local note about one stage. want_pass asks this note to treat a
 * unit note as a passed flagship stage.
 *
 * A unit note does not pass a flagship stage, so passed and demonstrated
 * stay false on every path.
 */
struct SwarmNotNoFlag {
    std::string stage_id;
    bool want_pass{false};
};

/**
 * Outcome of noting a stage. passed and demonstrated stay false on every
 * path: a unit note does not pass a flagship stage.
 */
struct SwarmNotNoFlagResult {
    std::string code;
    bool passed{false};
    bool demonstrated{false};
};

/**
 * Note a stage without passing a flagship stage.
 * Order, first match wins: an empty stage_id is STAGE. want_pass is
 * NOT_PASSED. Otherwise the note is NOTED and err is clear.
 * passed and demonstrated stay false on every path. A unit note does not
 * pass a flagship stage.
 */
SwarmNotNoFlagResult SwarmNoteNotNoFlag(const SwarmNotNoFlag& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFLAG_H
