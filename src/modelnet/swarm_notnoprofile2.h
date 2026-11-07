// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROFILE2_H
#define BTX_MODELNET_SWARM_NOTNOPROFILE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one launch profile. want_change asks this note to
 * change that profile.
 *
 * The launch profile stays BTX035-LAUNCH-DECODER-2x64. changed stays
 * false on every path.
 */
struct SwarmNotNoProfile2 {
    std::string profile_id;
    bool want_change{false};
};

/**
 * Outcome of noting a launch profile. changed stays false on every path.
 * The launch profile stays BTX035-LAUNCH-DECODER-2x64.
 */
struct SwarmNotNoProfile2Result {
    std::string code;
    bool changed{false};
};

/**
 * Note a launch profile without changing it.
 * Order, first match wins: an empty profile_id is PROFILE. want_change
 * is HELD. Otherwise the note is NOTED and err is clear.
 * changed stays false on every path. The launch profile stays
 * BTX035-LAUNCH-DECODER-2x64.
 */
SwarmNotNoProfile2Result SwarmNoteNotNoProfile2(const SwarmNotNoProfile2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROFILE2_H
