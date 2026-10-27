// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTZEROSTEP_H
#define BTX_MODELNET_SWARM_NOTZEROSTEP_H

#include <string>

namespace modelnet {

/**
 * A local note about a step count on one node. max_steps is the
 * requested count. want_train asks this note to train.
 *
 * Zero max steps stays CPU-only. This note trains nothing.
 * training stays false and applied_steps stays 0 on every path.
 */
struct SwarmNotZeroStep {
    std::string node_id;
    int max_steps{0};
    bool want_train{false};
};

/**
 * Outcome of noting a step count. training stays false and
 * applied_steps stays 0 on every path. This note trains nothing.
 */
struct SwarmNotZeroStepResult {
    std::string code;
    bool training{false};
    int applied_steps{0};
};

/**
 * Note a step count without training.
 * Order, first match wins: an empty node_id is NODE. If max_steps is
 * 0, the note is CPU_ONLY even when want_train is false. want_train is
 * CPU_ONLY. Otherwise the note is NOTED and err is clear.
 * training stays false and applied_steps stays 0 on every path.
 * Zero max steps stays CPU-only. This note trains nothing.
 */
SwarmNotZeroStepResult SwarmNoteNotZeroStep(const SwarmNotZeroStep& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTZEROSTEP_H
