// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TRAINWIRE_H
#define BITCOIN_MODELNET_SWARM_TRAINWIRE_H

#include <modelnet/swarm_disttrain/swarm_disttrain.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Step was asked for fewer than one update. The trainer is not called. */
inline constexpr char SWARM_TRAINWIRE_STEPS[] = "STEPS";

/** A GPU step was requested. No engine is present and Step is not called. */
inline constexpr char SWARM_TRAINWIRE_ENGINE_ABSENT[] = "ENGINE_ABSENT";

/** Recover was asked before any successful Step. */
inline constexpr char SWARM_TRAINWIRE_NOT_RESUMED[] = "NOT_RESUMED";

/**
 * Wire over the in-process integer trainer.
 *
 * Step calls SwarmDistTrain::Step. That trainer runs SwarmIntCycle on
 * two replicas and stores HexStr(Hash(hash_a + hash_b)). This class
 * reports that witness. It does not add an integer pair, invent a GPU
 * step, spawn a process, or fabricate a loss.
 *
 * steps below 1 sets err to STEPS and calls nothing.
 * Otherwise SwarmDistTrain::Step(steps, err) is called. On success,
 * witness() is that trainer's witness(), steps_done() is that
 * trainer's steps_done(), and trained() is true.
 *
 * GpuStep sets err to ENGINE_ABSENT and returns false. It does not
 * call Step. gpu() stays false. trained() stays as it was.
 *
 * Recover sets err to NOT_RESUMED and returns false when no successful
 * Step has happened. After a successful Step, Recover returns true.
 * witness() is unchanged. Recover does not run extra steps.
 *
 * launched(), gpu(), distributed_gpu(), and broadcast() stay false.
 * automatic_spend() stays "0". atoms_moved() stays 0.
 */
class SwarmTrainWire {
public:
    /**
     * Advance the integer trainer by `steps`.
     * steps below 1 sets err to STEPS and calls nothing.
     * Otherwise calls SwarmDistTrain::Step(steps, err). On failure
     * returns false and leaves trained() as it was.
     * On success, witness() is that trainer's witness(), steps_done()
     * is that trainer's steps_done(), trained() is true, and err is
     * cleared.
     */
    bool Step(uint64_t steps, std::string& err);

    /**
     * Refuse a GPU step. Always sets err to ENGINE_ABSENT and returns
     * false. Does not call Step. gpu() stays false. trained() stays
     * as it was. steps_done() stays unchanged.
     */
    bool GpuStep(uint64_t steps, std::string& err);

    /**
     * Report whether a successful Step has already happened.
     * When none has, sets err to NOT_RESUMED and returns false.
     * After a successful Step, returns true and leaves witness()
     * unchanged. Does not run extra steps.
     */
    bool Recover(std::string& err);

    /** SwarmDistTrain witness after a successful Step. Empty before that. */
    const std::string& witness() const;

    /** SwarmDistTrain steps_done() after a successful Step. */
    uint64_t steps_done() const;

    /** True after a successful Step. GpuStep does not change it. */
    bool trained() const;

    bool launched() const;
    bool gpu() const;
    bool distributed_gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    int64_t atoms_moved() const;

private:
    SwarmDistTrain m_trainer;
    bool m_trained{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TRAINWIRE_H
