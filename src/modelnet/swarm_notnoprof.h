// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROF_H
#define BTX_MODELNET_SWARM_NOTNOPROF_H

#include <string>

namespace modelnet {

/**
 * A local note about one launch profile. want_change asks this note to
 * change that profile.
 *
 * The launch profile stays fixed. changed and launched stay false on
 * every path.
 */
struct SwarmNotNoProf {
    std::string profile_id;
    bool want_change{false};
};

/**
 * Outcome of noting a launch profile. changed and launched stay false
 * on every path: the launch profile stays fixed.
 */
struct SwarmNotNoProfResult {
    std::string code;
    bool changed{false};
    bool launched{false};
};

/**
 * Note a launch profile without changing it.
 * Order, first match wins: an empty profile_id is PROFILE. A profile_id
 * that is not exactly BTX035-LAUNCH-DECODER-2x64 is FIXED even when
 * want_change is false. want_change is FIXED. Otherwise the note is NOTED
 * and err is clear.
 * changed and launched stay false on every path. The launch profile stays
 * fixed.
 */
SwarmNotNoProfResult SwarmNoteNotNoProf(const SwarmNotNoProf& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROF_H
