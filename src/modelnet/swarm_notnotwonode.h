// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOTWONODE_H
#define BTX_MODELNET_SWARM_NOTNOTWONODE_H

#include <string>

namespace modelnet {

/**
 * A local note about one job. want_train asks this note to treat
 * two-node training as a pass.
 *
 * Two-node training is not a pass.
 * trained and passed stay false on every path.
 */
struct SwarmNotNoTwoNode {
    std::string job_id;
    bool want_train{false};
};

/**
 * Outcome of noting two-node training. trained and passed stay false
 * on every path: two-node training is not a pass.
 */
struct SwarmNotNoTwoNodeResult {
    std::string code;
    bool trained{false};
    bool passed{false};
};

/**
 * Note two-node training without treating it as a pass.
 * Order, first match wins: an empty job_id is JOB.
 * want_train is UNQUALIFIED.
 * Otherwise the note is NOTED and err is clear.
 * trained and passed stay false on every path. Two-node training is
 * not a pass.
 */
SwarmNotNoTwoNodeResult SwarmNoteNotNoTwoNode(const SwarmNotNoTwoNode& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOTWONODE_H
