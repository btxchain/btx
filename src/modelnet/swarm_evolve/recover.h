// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVOLVE_RECOVER_H
#define BITCOIN_MODELNET_SWARM_EVOLVE_RECOVER_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Local recovery after the coordinator id is dropped.
 * Earned atoms are an argument and are not stored here, so this object
 * cannot change them. bytes_moved stays 0. mined stays false.
 */
class SwarmEvolveRecover {
public:
    void SetCoordinator(std::string coordinator_id);
    bool Recover(int64_t earned_atoms, bool checkpoint_present, const std::string& work_id, std::string& err);

    const std::string& CoordinatorId() const { return m_coordinator_id; }
    int64_t BytesMoved() const { return m_bytes_moved; }
    bool Mined() const { return m_mined; }

private:
    std::string m_coordinator_id;
    int64_t m_bytes_moved{0};
    bool m_mined{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVOLVE_RECOVER_H
