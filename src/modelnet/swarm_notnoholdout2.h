// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHOLDOUT2_H
#define BTX_MODELNET_SWARM_NOTNOHOLDOUT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one holdout. split_id names the split.
 * fixed marks a holdout that does not rotate. want_rotate asks this
 * note to rotate.
 *
 * A fixed holdout is not a rotating holdout. rotated and published
 * stay false on every path.
 */
struct SwarmNotNoHoldout2 {
    std::string split_id;
    bool fixed{false};
    bool want_rotate{false};
};

/**
 * Outcome of noting a holdout. rotated and published stay false on
 * every path. A fixed holdout is not a rotating holdout.
 */
struct SwarmNotNoHoldout2Result {
    std::string code;
    bool rotated{false};
    bool published{false};
};

/**
 * Note a holdout without rotating it or publishing it.
 * Order, first match wins: an empty split_id is SPLIT.
 * fixed is NOT_ROTATING even when want_rotate is false.
 * want_rotate is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * rotated and published stay false on every path.
 * A fixed holdout is not a rotating holdout.
 */
SwarmNotNoHoldout2Result SwarmNoteNotNoHoldout2(const SwarmNotNoHoldout2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHOLDOUT2_H
