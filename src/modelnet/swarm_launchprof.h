// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LAUNCHPROF_H
#define BTX_MODELNET_SWARM_LAUNCHPROF_H

#include <string>

namespace modelnet {

/**
 * A local note about one launch profile. want_change asks this note to
 * change the profile.
 *
 * The only accepted profile string is exactly BTX035-LAUNCH-DECODER-2x64.
 * changed stays false on every path. This note does not launch training.
 */
struct SwarmLaunchProf {
    std::string profile;
    bool want_change{false};
};

/**
 * Outcome of noting a launch profile. changed stays false on every path:
 * a requested change is held and does not launch training.
 */
struct SwarmLaunchProfResult {
    std::string code;
    bool changed{false};
};

/**
 * Note a launch profile without launching training.
 * Order, first match wins: an empty profile is PROFILE.
 * Any profile other than BTX035-LAUNCH-DECODER-2x64 is FIXED, even when
 * want_change is also true. want_change is HELD and err is clear.
 * Otherwise the note is NOTED and err is clear. changed stays false on
 * every path. This note does not launch training.
 */
SwarmLaunchProfResult SwarmNoteLaunchProf(const SwarmLaunchProf& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LAUNCHPROF_H
