// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOLDROT2_H
#define BTX_MODELNET_SWARM_NOTNOHOLDROT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one holdout. holdout_id names the holdout.
 * fixed_set marks a holdout that does not rotate. want_rotate asks
 * this note to rotate.
 *
 * A fixed holdout is not rotating. rotated stays false on every path.
 */
struct SwarmNotNoHoldRot2 {
    std::string holdout_id;
    bool fixed_set{false};
    bool want_rotate{false};
};

/**
 * Outcome of noting a holdout. rotated stays false on every path.
 * A fixed holdout is not rotating.
 */
struct SwarmNotNoHoldRot2Result {
    std::string code;
    bool rotated{false};
};

/**
 * Note a holdout without rotating it.
 * Order, first match wins: an empty holdout_id is HOLDOUT.
 * fixed_set is NOT_ROTATING even when want_rotate is false.
 * want_rotate is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * rotated stays false on every path.
 * A fixed holdout is not rotating.
 */
SwarmNotNoHoldRot2Result SwarmNoteNotNoHoldRot2(const SwarmNotNoHoldRot2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOLDROT2_H
