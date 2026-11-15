// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOLDOUTROT2_H
#define BTX_MODELNET_SWARM_NOTNOHOLDOUTROT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one holdout. holdout_id names the holdout.
 * fixed marks a holdout that does not rotate. want_rotate asks this
 * note to rotate.
 *
 * A fixed holdout is not rotating. rotated stays false on every path.
 */
struct SwarmNotNoHoldoutRot2 {
    std::string holdout_id;
    bool fixed{false};
    bool want_rotate{false};
};

/**
 * Outcome of noting a holdout. rotated stays false on every path.
 * A fixed holdout is not rotating.
 */
struct SwarmNotNoHoldoutRot2Result {
    std::string code;
    bool rotated{false};
};

/**
 * Note a holdout without rotating it.
 * Order, first match wins: an empty holdout_id is HOLDOUT.
 * fixed is NOT_ROTATED even when want_rotate is false.
 * want_rotate is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * rotated stays false on every path.
 * A fixed holdout is not rotating.
 */
SwarmNotNoHoldoutRot2Result SwarmNoteNotNoHoldoutRot2(const SwarmNotNoHoldoutRot2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOLDOUTROT2_H
