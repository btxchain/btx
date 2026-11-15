// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CONFLICT_H
#define BTX_MODELNET_SWARM_CONFLICT_H

#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory record of the first hash offered for a task.
 * A later offer of a different hash is CONFLICT and leaves the first hash
 * in place. Conflicting hashes are not averaged or blended.
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or address.
 */
class SwarmConflict {
public:
    /**
     * An empty task, worker, or hash is TASK and stores nothing.
     * The first offer for a task stores that hash and worker and clears err.
     * The same worker and the same hash again clears err and returns true.
     * A different worker offering that same hash also clears err and returns
     * true, and leaves the first worker and hash in place.
     * A different hash for the same task is CONFLICT, returns false, marks
     * the task conflicted, and keeps the first hash. The hashes are not blended.
     */
    bool Offer(const std::string& task, const std::string& worker, const std::string& hash, std::string& err);

    /** The stored hash, or empty when the task is unknown. */
    std::string Hash(const std::string& task) const;

    /** True only after an offer for this task returned CONFLICT. */
    bool conflicted(const std::string& task) const;

private:
    struct OfferRow {
        std::string worker;
        std::string hash;
        bool conflicted{false};
    };

    std::map<std::string, OfferRow> m_offers;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CONFLICT_H
