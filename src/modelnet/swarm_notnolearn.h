// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOLEARN_H
#define BTX_MODELNET_SWARM_NOTNOLEARN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one learner. want_spend asks this note to spend.
 *
 * A learner note spends nothing. spent stays false and atoms stays 0 on
 * every path.
 */
struct SwarmNotNoLearn {
    std::string learner_id;
    bool want_spend{false};
};

/**
 * Outcome of noting a learner. spent stays false and atoms stays 0 on
 * every path. A learner note spends nothing.
 */
struct SwarmNotNoLearnResult {
    std::string code;
    bool spent{false};
    int64_t atoms{0};
};

/**
 * Note a learner without spending.
 * Order, first match wins: an empty learner_id is LEARNER.
 * want_spend is HELD.
 * Otherwise the note is NOTED and err is clear.
 * spent stays false and atoms stays 0 on every path. A learner note
 * spends nothing.
 */
SwarmNotNoLearnResult SwarmNoteNotNoLearn(const SwarmNotNoLearn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOLEARN_H
