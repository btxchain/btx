// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROF_RECORD_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROF_RECORD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * One recorded rename.
 * The record holds the name only. renamed stays false.
 * bytes_moved stays 0. gpu stays false. launched stays false.
 * The profile string is not stored here.
 * Make is the only writer of those fields. There is no setter
 * and no method that renames the profile.
 */
class SwarmLaunchProfileRecord {
public:
    static SwarmLaunchProfileRecord Make(const std::string& name);

    const std::string& name() const { return m_name; }
    bool renamed() const { return m_renamed; }
    int64_t bytes_moved() const { return m_bytes_moved; }
    bool gpu() const { return m_gpu; }
    bool launched() const { return m_launched; }

private:
    std::string m_name;
    bool m_renamed{false};
    int64_t m_bytes_moved{0};
    bool m_gpu{false};
    bool m_launched{false};
};

/**
 * The name is non-empty, the profile is not renamed, no bytes moved,
 * the gpu is idle, and nothing was launched.
 */
bool SwarmLaunchProfileRecordUsable(const SwarmLaunchProfileRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROF_RECORD_H
