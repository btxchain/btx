// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFLAGSHIP_H
#define BTX_MODELNET_SWARM_NOTFLAGSHIP_H

#include <string>

namespace modelnet {

/**
 * A local note that a unit might pass a 13-stage flagship demo.
 * want_pass asks this note to treat the demo as passed.
 *
 * A unit note is not a passed 13-stage flagship demo, so passed stays false
 * on every path.
 */
struct SwarmNotFlagship {
    std::string stage_id;
    bool want_pass{false};
};

/**
 * Outcome of noting that a unit note is not a passed 13-stage flagship demo.
 * passed stays false on every path.
 */
struct SwarmNotFlagshipResult {
    std::string code;
    bool passed{false};
};

/**
 * Note that a unit note is not a passed 13-stage flagship demo.
 * Order, first match wins: an empty stage_id is STAGE. want_pass is
 * UNQUALIFIED. Otherwise the note is NOTED and err is clear.
 * passed stays false on every path. A unit note is not a passed 13-stage
 * flagship demo.
 */
SwarmNotFlagshipResult SwarmNoteNotFlagship(const SwarmNotFlagship& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFLAGSHIP_H
