// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLAUNCHPROF2_H
#define BTX_MODELNET_SWARM_NOTNOLAUNCHPROF2_H

#include <string>

namespace modelnet {

/**
 * A local note about one launch profile. want_rename asks this note to
 * rename that profile.
 *
 * The launch profile stays BTX035-LAUNCH-DECODER-2x64. renamed stays
 * false on every path.
 */
struct SwarmNotNoLaunchProf2 {
    std::string profile_id;
    bool want_rename{false};
};

/**
 * Outcome of noting a launch profile. renamed stays false on every path.
 * The launch profile stays BTX035-LAUNCH-DECODER-2x64.
 */
struct SwarmNotNoLaunchProf2Result {
    std::string code;
    bool renamed{false};
};

/**
 * Note a launch profile without renaming it.
 * Order, first match wins: an empty profile_id is PROFILE. want_rename
 * is HELD. Otherwise the note is NOTED and err is clear.
 * renamed stays false on every path. The launch profile stays
 * BTX035-LAUNCH-DECODER-2x64.
 */
SwarmNotNoLaunchProf2Result SwarmNoteNotNoLaunchProf2(const SwarmNotNoLaunchProf2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLAUNCHPROF2_H
