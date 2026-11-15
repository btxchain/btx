// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ABLATEHOLD_RECORD_H
#define BITCOIN_MODELNET_SWARM_ABLATEHOLD_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded ablation publish request.
 * The record holds the name only. published stays false.
 * bytes_moved stays 0. gpu stays false. launched stays false.
 * Make is the only writer of those fields. There is no setter
 * and no method that publishes the request.
 */
class SwarmAblateHoldRecord {
public:
    static SwarmAblateHoldRecord Make(const std::string& name);

    const std::string& name() const { return m_name; }
    bool published() const { return m_published; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }

private:
    std::string m_name;
    bool m_published{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
};

/**
 * The name is non-empty, the request is not published, no bytes moved,
 * the gpu is idle, and nothing was launched.
 */
bool SwarmAblateHoldRecordUsable(const SwarmAblateHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ABLATEHOLD_RECORD_H
