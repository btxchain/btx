// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REWARDLOOP_H
#define BTX_MODELNET_SWARM_REWARDLOOP_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory reward rows and a learner queue of their ids.
 * The reward is computed from outcome_ppm. It is not copied from a caller
 * reward field. A kind other than a public or synthetic trajectory is
 * refused and stores nothing. This loop does not broadcast, spend, spawn
 * a child process, open a network connection, or record a hostname or address.
 */
class SwarmRewardLoop {
public:
    /**
     * Order: an empty id is ITEM. A kind other than "public_trajectory" or
     * "synthetic_trajectory" is PRIVATE_DATA and stores nothing. outcome_ppm
     * below 0 or above 1000000 is RANGE. A duplicate id is REPLAY and the
     * stored row stays the first one. Otherwise the row is stored. The
     * reward is 1 when outcome_ppm is at least 500000, and 0 otherwise.
     * Success clears err.
     */
    bool Store(const std::string& id, const std::string& kind, int64_t outcome_ppm, std::string& err);

    /** The computed reward for a stored id, or -1 when the id is absent. */
    int reward(const std::string& id) const;

    /**
     * Order: an id that was not stored is ITEM. An id already in the learner
     * queue is REPLAY. Otherwise the id is appended in order. Success clears err.
     */
    bool Enqueue(const std::string& id, std::string& err);

    /** Learner queue in enqueue order. */
    const std::vector<std::string>& Queue() const;

private:
    struct Row {
        std::string kind;
        int64_t outcome_ppm{0};
        int reward{0};
    };

    std::map<std::string, Row> m_rows;
    std::vector<std::string> m_queue;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REWARDLOOP_H
