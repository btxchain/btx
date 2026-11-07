// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TRAJECTORY_H
#define BTX_MODELNET_SWARM_TRAJECTORY_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One rollout queued under a bound policy version. learned and
 * policy_updated stay false. This queue does not run a learner.
 */
struct SwarmTrajectoryItem {
    std::string example_id;
    std::string origin;
    bool rights_authorized{false};
    std::string source_evidence;
};

struct SwarmTrajectoryRow {
    SwarmTrajectoryItem item;
    bool learned{false};
    bool policy_updated{false};
    bool bytes_moved{false};
};

/**
 * Policy-versioned trajectory queue. Private and credential origins stay
 * out. Dequeue does not update a policy and does not move bytes.
 */
class SwarmTrajectoryQueue {
public:
    /** Empty version is POLICY. The same version again is idempotent. A different version is STALE_POLICY. */
    bool BindPolicy(const std::string& policy_version, std::string& err);
    /** Enqueue under the bound policy. The stored row is not learned. */
    bool Enqueue(const SwarmTrajectoryItem& item, std::string& err);
    /** Copies the oldest row out and removes it. The three flags stay false. */
    bool Dequeue(SwarmTrajectoryRow& out, std::string& err);
    std::string Policy() const;
    std::size_t Size() const;

private:
    std::string m_policy;
    std::vector<SwarmTrajectoryRow> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TRAJECTORY_H
