// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLVE_TRAIN_GATE_H
#define BITCOIN_MODELNET_SWARM_EVOLVE_TRAIN_GATE_H

#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One integer step for the current generation.
 * IntegerDataset stays at eight pairs. IntegerTrainer::Step runs once,
 * and the step is stored only when ReplayMatches accepts that state.
 * A second call in the same generation is REPLAY and does not step again.
 * GpuRan stays false: this gate does not claim a GPU ran.
 */
class SwarmEvolveTrain {
public:
    bool Train(std::string& err);
    void Reset();

    bool Trained() const { return m_trained; }
    uint64_t StepIndex() const { return m_step; }
    const std::string& StateHash() const { return m_state_hash; }
    const IntegerState& State() const { return m_state; }
    bool GpuRan() const { return m_gpu_ran; }

private:
    bool m_trained{false};
    bool m_stepped{false};
    bool m_gpu_ran{false};
    uint64_t m_step{0};
    std::string m_state_hash;
    IntegerState m_state;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLVE_TRAIN_GATE_H
