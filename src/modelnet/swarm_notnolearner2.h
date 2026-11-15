// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLEARNER2_H
#define BTX_MODELNET_SWARM_NOTNOLEARNER2_H

#include <string>

namespace modelnet {

/**
 * A local note about one learner. want_run asks this note to run.
 *
 * A learner has not run and this note runs nothing.
 * running stays false on every path.
 */
struct SwarmNotNoLearner2 {
    std::string learner_id;
    bool want_run{false};
};

/**
 * Outcome of noting a learner. running stays false on every path.
 * A learner has not run and this note runs nothing.
 */
struct SwarmNotNoLearner2Result {
    std::string code;
    bool running{false};
};

/**
 * Note a learner without running it.
 * Order, first match wins: an empty learner_id is LEARNER.
 * want_run is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * running stays false on every path.
 * A learner has not run and this note runs nothing.
 */
SwarmNotNoLearner2Result SwarmNoteNotNoLearner2(const SwarmNotNoLearner2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLEARNER2_H
