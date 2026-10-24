// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGAIN_H
#define BTX_MODELNET_SWARM_NOTNOGAIN_H

#include <string>

namespace modelnet {

/**
 * A local note about one training step. want_claim asks this note to
 * treat that step as a quality gain.
 *
 * One training step is not a quality gain. gained and evaluated stay
 * false on every path.
 */
struct SwarmNotNoGain {
    std::string step_id;
    bool want_claim{false};
};

/**
 * Outcome of noting one training step. gained and evaluated stay false
 * on every path: one training step is not a quality gain.
 */
struct SwarmNotNoGainResult {
    std::string code;
    bool gained{false};
    bool evaluated{false};
};

/**
 * Note one training step without treating it as a quality gain.
 * Order, first match wins: an empty step_id is STEP. want_claim is
 * NOT_EVALUATED. Otherwise the note is NOTED and err is clear.
 * gained and evaluated stay false on every path. One training step is
 * not a quality gain.
 */
SwarmNotNoGainResult SwarmNoteNotNoGain(const SwarmNotNoGain& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGAIN_H
