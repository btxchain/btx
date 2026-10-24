// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LEADEREPOCH_H
#define BTX_MODELNET_SWARM_LEADEREPOCH_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory leader epoch. The epoch starts at 1 and the leader starts empty.
 * Claim records the leader for the current epoch. Bump advances the epoch and
 * clears the leader, so the previous leader can no longer assign. Assign stores
 * one task for the current leader and epoch. A stored task stays stored across
 * a bump, so the same task is still a replay.
 *
 * This record does not broadcast, spend, spawn a child process, open a network
 * connection, or record a hostname or address.
 */
class SwarmLeaderEpoch {
public:
    /**
     * An empty leader is LEADER and leaves the stored leader. An epoch other
     * than the current epoch is STALE_EPOCH and leaves the stored leader.
     * Success sets the leader and clears err.
     */
    bool Claim(const std::string& leader, int64_t epoch, std::string& err);

    /** Increment the epoch by 1 and clear the leader. */
    void Bump();

    /**
     * Order, first match wins: a leader other than the current leader, or an
     * epoch other than the current epoch, is STALE_EPOCH and stores nothing.
     * An empty task is TASK and stores nothing. A task already stored is
     * REPLAY and leaves that assignment. Otherwise the assignment is stored
     * and err is cleared.
     */
    bool Assign(const std::string& leader, int64_t epoch, const std::string& task, std::string& err);

    /** Current leader. Empty until a claim succeeds, and empty again after Bump. */
    std::string Leader() const;

    /** Current epoch. Starts at 1. */
    int64_t epoch() const;

private:
    struct Assignment {
        std::string leader;
        int64_t epoch{0};
    };

    std::string m_leader;
    int64_t m_epoch{1};
    std::map<std::string, Assignment> m_assignments;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LEADEREPOCH_H
