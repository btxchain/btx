// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_LEADER_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_LEADER_H

#include <string>

namespace modelnet {

/**
 * Leader right to commit for the current epoch.
 * Epoch 1 starts with no leader and no commit right.
 * Claim installs one worker and sets the right. Clear drops both.
 * A second claim does not replace the worker.
 */
class LeaseWorkLeader {
public:
    bool right() const;
    bool claimed() const;
    const std::string& worker() const;

    /** Install worker and set the commit right. Refuses an empty worker or a second claim. */
    bool Claim(const std::string& worker);

    /** Drop the leader and the commit right. */
    void Clear();

private:
    std::string m_worker;
    bool m_right{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_LEADER_H
