// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPASSTHRU2_H
#define BTX_MODELNET_SWARM_NOTNOPASSTHRU2_H

#include <string>

namespace modelnet {

/**
 * A local note about GPU passthrough. passthrough asks this note to treat
 * the check as a live passthrough. want_start asks this note to start it.
 *
 * GPU passthrough is not started, so started stays false on every path.
 */
struct SwarmNotNoPassThru2 {
    std::string check_id;
    bool passthrough{false};
    bool want_start{false};
};

/**
 * Outcome of noting GPU passthrough. started stays false on every path:
 * GPU passthrough is not started.
 */
struct SwarmNotNoPassThru2Result {
    std::string code;
    bool started{false};
};

/**
 * Note GPU passthrough without starting it.
 * Order, first match wins: an empty check_id is CHECK.
 * passthrough is NOT_STARTED, even when want_start is false.
 * want_start is HELD.
 * Otherwise the note is NOTED and err is clear.
 * started stays false on every path. GPU passthrough is not started.
 */
SwarmNotNoPassThru2Result SwarmNoteNotNoPassThru2(const SwarmNotNoPassThru2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPASSTHRU2_H
