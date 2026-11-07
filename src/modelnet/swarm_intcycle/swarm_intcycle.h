// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_INTCYCLE_H
#define BITCOIN_MODELNET_SWARM_INTCYCLE_H

#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Run was asked for fewer than one step. The trainer is not called. */
inline constexpr char SWARM_INTCYCLE_STEPS[] = "STEPS";

/** A GPU step was requested. No engine is present and no step is taken. */
inline constexpr char SWARM_INTCYCLE_ENGINE_ABSENT[] = "ENGINE_ABSENT";

/** Gradient export was requested. No gradient bytes are written. */
inline constexpr char SWARM_INTCYCLE_NOT_EXPORTED[] = "NOT_EXPORTED";

/**
 * In-process integer training cycle.
 *
 * Run and Resume call modelnet::IntegerTrainer. The dataset is the frozen
 * eight pairs from IntegerDataset(). This cycle does not add an example,
 * mark a GPU run, mark FSDP, or mark a distributed checkpoint.
 *
 * gpu(), distributed(), launched(), and broadcast() stay false.
 * automatic_spend() stays "0". atoms_moved() and bytes_moved() stay 0.
 */
class SwarmIntCycle {
public:
    /**
     * Take `steps` updates on the integer trainer.
     * steps below 1 sets err to STEPS and does not call the trainer.
     * Otherwise calls trainer.Run(steps, err). On success stores
     * IntegerStateHash of the trainer state and that state's step count,
     * clears err, and returns true. On failure the stored hash and step
     * count stay as they were and err is the trainer's err.
     */
    bool Run(uint64_t steps, std::string& err);

    /**
     * Continue from a committed checkpoint by calling trainer.Resume.
     * A checkpoint step of 0 is the trainer's NOT_RESUMABLE path and stays
     * a failure. After a successful resume, stores the new hash and step.
     * A failed resume leaves the stored hash and step count unchanged.
     */
    bool Resume(const IntegerState& checkpoint, std::string& err);

    /**
     * Refuse a GPU run. Always sets err to ENGINE_ABSENT and returns false.
     * Does not call the trainer. gpu() stays false. The stored step count
     * stays unchanged.
     */
    bool GpuRun(uint64_t steps, std::string& err);

    /**
     * Refuse gradient export. Always sets err to NOT_EXPORTED and returns
     * false. Does not serialize a gradient. bytes_moved() stays 0.
     */
    bool ExportGrad(std::string& err);

    uint64_t steps() const;
    const std::string& state_hash() const;
    bool gpu() const;
    bool distributed() const;
    bool launched() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    int64_t atoms_moved() const;
    int64_t bytes_moved() const;

    /** Trainer state after the last successful Run or Resume. */
    const IntegerState& State() const;

private:
    IntegerTrainer m_trainer;
    uint64_t m_steps{0};
    std::string m_state_hash;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_INTCYCLE_H
