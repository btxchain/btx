// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSEQUENCE_H
#define BTX_MODELNET_SWARM_NOTSEQUENCE_H

#include <string>

namespace modelnet {

/**
 * A local note about one sequence step on a channel. A clearing close
 * uses one sequence step. want_step asks this note to take that step.
 *
 * This note does not take a sequence step. stepped stays false and
 * applied_steps stays 0 on every path.
 */
struct SwarmNotSequence {
    std::string channel_id;
    int step_count{0};
    bool want_step{false};
};

/**
 * Outcome of noting a sequence step. stepped stays false and
 * applied_steps stays 0 on every path.
 */
struct SwarmNotSequenceResult {
    std::string code;
    bool stepped{false};
    int applied_steps{0};
};

/**
 * Note a sequence step without taking it.
 * Order, first match wins: an empty channel_id is CHANNEL. If step_count
 * is not 1, the note is ONE_STEP, even when want_step is false. want_step
 * is ONE_STEP. Otherwise the note is NOTED and err is clear.
 * stepped stays false and applied_steps stays 0 on every path.
 * A clearing close uses one sequence step.
 */
SwarmNotSequenceResult SwarmNoteNotSequence(const SwarmNotSequence& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSEQUENCE_H
