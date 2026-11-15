// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ISLANDOPT_H
#define BTX_MODELNET_SWARM_ISLANDOPT_H

#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One local INTEGER_LINEAR island. It holds one IntegerTrainer and steps
 * that trainer in process. A remote update is stored as a pending hash and
 * does not replace the local weight, bias, or state hash. Averaging a
 * remote update into the local weights is refused. bytes_moved stays 0.
 * INTEGER_LINEAR stays eight frozen pairs.
 */
class SwarmIslandOpt {
public:
    bool LocalStep(std::string& err);
    bool AcceptRemote(uint64_t remote_step, const std::string& remote_hash, bool stale, std::string& err);
    bool RejectAverage(std::string& err);

    uint64_t steps() const { return m_steps; }
    const std::string& state_hash() const { return m_state_hash; }
    int64_t bytes_moved() const { return 0; }
    const std::string& pending_hash() const { return m_pending_hash; }

private:
    IntegerTrainer m_trainer;
    uint64_t m_steps{0};
    std::string m_state_hash;
    std::string m_pending_hash;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ISLANDOPT_H
