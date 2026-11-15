// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_RECORD_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded guest-agent check.
 * The record holds the name only. passed stays false.
 * logged_in stays false. bytes_moved stays 0.
 * gpu stays false. launched stays false.
 * Make is the only writer of those fields. There is no setter,
 * no pass method, and no login method.
 */
class SwarmGuestHoldRecord {
public:
    static SwarmGuestHoldRecord Make(const std::string& name);

    const std::string& name() const { return m_name; }
    bool passed() const { return m_passed; }
    bool logged_in() const { return m_logged_in; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }

private:
    std::string m_name;
    bool m_passed{false};
    bool m_logged_in{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
};

/**
 * The name is non-empty, the check did not pass, the agent is not
 * logged in, no bytes moved, the gpu is idle, and nothing was launched.
 */
bool SwarmGuestHoldRecordUsable(const SwarmGuestHoldRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_RECORD_H
