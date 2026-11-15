// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_H

#include <modelnet/swarm_experience/queue.h>
#include <modelnet/swarm_experience/store.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Authorized experience plane.
 * Store keeps public_trajectory and synthetic_trajectory rows only.
 * Reward is computed from the stored outcome_ppm, never supplied.
 * Enqueue lists stored ids in insertion order and does not repeat them.
 * TrainFrom records that a stored id was offered. It does not run a GPU
 * and does not add an integer pair. bytes_moved() is 0, gpu() is false,
 * and private_stored() is false.
 */
class SwarmExperience {
public:
    bool Store(const std::string& id, const std::string& kind, int64_t outcome_ppm, std::string& err);
    int reward(const std::string& id) const;
    void Enqueue();
    const std::vector<std::string>& queued() const { return m_queue.ids(); }
    bool TrainFrom(const std::string& id, std::string& err);
    bool offered(const std::string& id) const;
    uint64_t bytes_moved() const;
    bool gpu() const;
    bool private_stored() const;
    std::size_t size() const { return m_store.size(); }

private:
    ExperienceStore m_store;
    ExperienceQueue m_queue;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_H
