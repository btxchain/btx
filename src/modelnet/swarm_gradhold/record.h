// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GRADHOLD_RECORD_H
#define BITCOIN_MODELNET_SWARM_GRADHOLD_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded gradient update.
 * The record holds the update id only. exported stays false.
 * bytes_moved stays 0. gpu stays false. launched stays false.
 * Make is the only writer of those fields. There is no setter
 * and no export method.
 */
class SwarmGradHoldRecord {
public:
    static SwarmGradHoldRecord Make(const std::string& update_id);

    const std::string& update_id() const { return m_update_id; }
    bool exported() const { return m_exported; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }

private:
    std::string m_update_id;
    bool m_exported{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
};

/**
 * The id is non-empty, the update is not exported, no bytes moved,
 * the gpu is idle, and nothing was launched.
 */
bool SwarmGradHoldRecordUsable(const SwarmGradHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GRADHOLD_RECORD_H
