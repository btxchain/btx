// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MINEHOLD_RECORD_H
#define BITCOIN_MODELNET_SWARM_MINEHOLD_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded mine request.
 * The record holds the name only. mined stays false. blocks stays 0.
 * bytes_moved stays 0. broadcast stays false. gpu stays false.
 * Make is the only writer of those fields. There is no setter
 * and no method that mines the request.
 */
class SwarmMineHoldRecord {
public:
    static SwarmMineHoldRecord Make(const std::string& name);

    const std::string& name() const { return m_name; }
    bool mined() const { return m_mined; }
    int64_t blocks() const { return m_blocks; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool broadcast() const { return m_broadcast; }
    bool gpu() const { return m_gpu; }

private:
    std::string m_name;
    bool m_mined{false};
    int64_t m_blocks{0};
    int64_t m_bytes_moved{0};
    bool m_broadcast{false};
    bool m_gpu{false};
};

/**
 * The name is non-empty, the request is not mined, no blocks were mined,
 * no bytes moved, nothing was broadcast, and the gpu is idle.
 */
bool SwarmMineHoldRecordUsable(const SwarmMineHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MINEHOLD_RECORD_H
