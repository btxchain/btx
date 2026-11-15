// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LOGINHOLD_RECORD_H
#define BITCOIN_MODELNET_SWARM_LOGINHOLD_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded login request.
 * The record holds the name only. logged_in stays false.
 * bytes_moved stays 0. gpu stays false. launched stays false.
 * Make is the only writer of those fields. There is no setter
 * and no login method.
 */
class SwarmLoginHoldRecord {
public:
    static SwarmLoginHoldRecord Make(const std::string& name);

    const std::string& name() const { return m_name; }
    bool logged_in() const { return m_logged_in; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }

private:
    std::string m_name;
    bool m_logged_in{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
};

/**
 * The name is non-empty, the request is not logged in, no bytes moved,
 * the gpu is idle, and nothing was launched.
 */
bool SwarmLoginHoldRecordUsable(const SwarmLoginHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LOGINHOLD_RECORD_H
