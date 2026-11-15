// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STEPWORK_H
#define BITCOIN_MODELNET_SWARM_STEPWORK_H

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Stores one authorized experience row from a real integer training step.
 *
 * Record runs SwarmIntCycle and stores the result through SwarmExperience.
 * This module does not reimplement the trainer or the experience store,
 * does not add an integer pair, and does not mark a GPU run.
 *
 * Record: an empty id is WORK and stores nothing. is_private true is
 * PRIVATE_DATA and stores nothing. steps below 1 is STEPS and does not
 * call the trainer. Otherwise Run(steps) is called. A failed Run returns
 * the trainer error and does not store. On success the id is stored as
 * public_trajectory with outcome_ppm equal to steps * 1000. A failed
 * Store returns the store error. Enqueue() then lists the stored id.
 * A second Record of the same id is REPLAY and does not run more steps.
 *
 * Offer: an unknown id is WORK. Otherwise TrainFrom(id) records an offer.
 * Offer does not run a GPU.
 *
 * GpuRecord always returns ENGINE_ABSENT. It does not call Run or Store.
 *
 * reward_of(id) is experience.reward(id), computed from the stored
 * outcome_ppm. The caller does not supply a reward.
 * state_hash() is the cycle state_hash(). gpu() stays false.
 * private_stored() stays false.
 */
class SwarmStepWork {
public:
    bool Record(const std::string& id, int64_t steps, bool is_private, std::string& err);
    bool Offer(const std::string& id, std::string& err);
    bool GpuRecord(const std::string& id, int64_t steps, std::string& err);

    const std::string& state_hash() const;
    int reward_of(const std::string& id) const;
    bool offered(const std::string& id) const;
    std::size_t queued_count() const;
    bool gpu() const;
    bool private_stored() const;

    /** Stored experience rows. A refused record leaves this unchanged. */
    std::size_t size() const;

private:
    SwarmIntCycle m_cycle;
    SwarmExperience m_experience;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STEPWORK_H
