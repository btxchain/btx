// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_QUEUE_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_QUEUE_H

#include <modelnet/swarm_experience/row.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Ids of stored trajectories in insertion order.
 * A second pass appends only ids that are not already queued.
 * An empty id or a refused kind is skipped.
 */
class ExperienceQueue {
public:
    void Enqueue(const std::vector<ExperienceRow>& rows);
    const std::vector<std::string>& ids() const { return m_ids; }

private:
    bool Contains(const std::string& id) const;

    std::vector<std::string> m_ids;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_QUEUE_H
