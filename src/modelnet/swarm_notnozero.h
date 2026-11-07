// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOZERO_H
#define BTX_MODELNET_SWARM_NOTNOZERO_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about a step count on one run. max_steps is the
 * requested count. want_train asks this note to train.
 *
 * Zero max steps stays CPU-only and this note trains nothing.
 * training stays false and applied_steps stays 0 on every path.
 */
struct SwarmNotNoZero {
    std::string run_id;
    int64_t max_steps{0};
    bool want_train{false};
};

/**
 * Outcome of noting a step count. training stays false and
 * applied_steps stays 0 on every path. This note trains nothing.
 */
struct SwarmNotNoZeroResult {
    std::string code;
    bool training{false};
    int64_t applied_steps{0};
};

/**
 * Note a step count without training.
 * Order, first match wins: an empty run_id is RUN. If max_steps is
 * 0, the note is CPU_ONLY even when want_train is false. want_train is
 * CPU_ONLY. Otherwise the note is NOTED and err is clear.
 * training stays false and applied_steps stays 0 on every path.
 * Zero max steps stays CPU-only and this note trains nothing.
 */
SwarmNotNoZeroResult SwarmNoteNotNoZero(const SwarmNotNoZero& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOZERO_H
