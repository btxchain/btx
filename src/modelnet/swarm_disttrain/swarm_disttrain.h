// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISTTRAIN_H
#define BITCOIN_MODELNET_SWARM_DISTTRAIN_H

#include <modelnet/swarm_intcycle/swarm_intcycle.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Step was asked for fewer than one update. Neither replica is called. */
inline constexpr char SWARM_DISTTRAIN_STEPS[] = "STEPS";

/** A GPU, FSDP, or DiLoCo step was requested. No engine is present. */
inline constexpr char SWARM_DISTTRAIN_ENGINE_ABSENT[] = "ENGINE_ABSENT";

/** Gradient export was requested. No gradient bytes are written. */
inline constexpr char SWARM_DISTTRAIN_NOT_EXPORTED[] = "NOT_EXPORTED";

/**
 * Two in-process integer replicas.
 *
 * Step calls SwarmIntCycle::Run on worker_a and then worker_b. The
 * dataset stays the frozen eight pairs inside that cycle. This class
 * does not add an example and does not pretend a GPU is present.
 *
 * steps below 1 sets err to STEPS and calls neither Run.
 * Otherwise worker_a.Run(steps, err) is called. A failed Run returns
 * false, does not call worker_b, and does not store a witness.
 * worker_b.Run(steps, err) is called only after worker_a succeeds. A
 * failed second Run does not store a witness. worker_a has already
 * advanced, so steps_done() may reflect worker_a.
 * On both success, witness() is HexStr(Hash(hash_a + hash_b)), where
 * hash_a and hash_b are the two state_hash() strings.
 *
 * steps_done() is worker_a.steps() + worker_b.steps() after a stored
 * witness, and 0 when no witness is stored and worker_a has not run.
 *
 * GpuStep, FsdpStep, and DilocoStep always set err to ENGINE_ABSENT
 * and return false. They do not call Run. gpu(), distributed_gpu(),
 * and launched() stay false. No method sets them true.
 * ExportGrad sets err to NOT_EXPORTED and returns false.
 * broadcast() stays false. automatic_spend() stays "0".
 * atoms_moved() stays 0.
 */
class SwarmDistTrain {
public:
    /**
     * Advance both integer replicas by `steps`.
     * steps below 1 sets err to STEPS and calls neither Run.
     * Otherwise calls worker_a.Run(steps, err). On failure returns false
     * without calling worker_b and without storing a witness.
     * Then calls worker_b.Run(steps, err). On failure returns false
     * without storing a witness. steps_done() may reflect worker_a.
     * On both success stores HexStr(Hash(hash_a + hash_b)), clears err,
     * and returns true.
     */
    bool Step(uint64_t steps, std::string& err);

    /**
     * Refuse a GPU step. Always sets err to ENGINE_ABSENT and returns
     * false. Does not call Run. steps_done() stays unchanged. gpu()
     * stays false.
     */
    bool GpuStep(uint64_t steps, std::string& err);

    /**
     * Refuse an FSDP step. Always sets err to ENGINE_ABSENT and returns
     * false. Does not call Run. steps_done() stays unchanged.
     * distributed_gpu() stays false.
     */
    bool FsdpStep(uint64_t steps, std::string& err);

    /**
     * Refuse a DiLoCo step. Always sets err to ENGINE_ABSENT and returns
     * false. Does not call Run. steps_done() stays unchanged.
     * distributed_gpu() stays false.
     */
    bool DilocoStep(uint64_t steps, std::string& err);

    /**
     * Refuse gradient export. Always sets err to NOT_EXPORTED and returns
     * false. Does not serialize a gradient. atoms_moved() stays 0.
     */
    bool ExportGrad(std::string& err);

    /** HexStr(Hash(hash_a + hash_b)) after both replicas succeed. Empty before that. */
    const std::string& witness() const;

    /**
     * worker_a.steps() + worker_b.steps() after a stored witness.
     * 0 when no witness is stored and worker_a has not run.
     * If worker_b.Run fails, no witness is stored for that attempt and
     * this count may reflect worker_a.
     */
    uint64_t steps_done() const;

    bool gpu() const;
    bool distributed_gpu() const;
    bool launched() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    int64_t atoms_moved() const;

private:
    SwarmIntCycle worker_a;
    SwarmIntCycle worker_b;
    std::string m_witness;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISTTRAIN_H
