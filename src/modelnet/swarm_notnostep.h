// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSTEP_H
#define BTX_MODELNET_SWARM_NOTNOSTEP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about a training step. step_id names the step. steps is
 * the step count. want_distributed asks this note to treat the count as
 * distributed training.
 *
 * One local step is not FSDP. distributed stays false, and trained stays
 * false, on every path.
 */
struct SwarmNotNoStep {
    std::string step_id;
    int64_t steps{0};
    bool want_distributed{false};
};

/**
 * Outcome of noting a training step. distributed stays false, and trained
 * stays false, on every path. One local step is not FSDP.
 */
struct SwarmNotNoStepResult {
    std::string code;
    bool distributed{false};
    bool trained{false};
};

/**
 * Note a training step without treating one local step as FSDP. Order,
 * first match wins: an empty step_id is STEP. A steps value that is not
 * greater than 1 is NOT_DISTRIBUTED, even when want_distributed is false.
 * want_distributed is NOT_DISTRIBUTED. Otherwise the note is NOTED and err
 * is clear. One local step is not FSDP. distributed stays false, and
 * trained stays false, on every path.
 */
SwarmNotNoStepResult SwarmNoteNotNoStep(const SwarmNotNoStep& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSTEP_H
