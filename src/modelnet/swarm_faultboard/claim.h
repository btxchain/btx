// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_CLAIM_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_CLAIM_H

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Durable claims for one swarm, one worker per task.
 * Keep stores a new task. The same pair is accepted again.
 * A different worker for a stored task is refused and the first stays.
 * There is no erase.
 */
class SwarmFaultClaimBook {
public:
    bool Keep(const std::string& task, const std::string& worker, std::string& err);
    bool contains(const std::string& task) const;
    std::string worker_for(const std::string& task) const;
    std::size_t count() const;

private:
    std::map<std::string, std::string> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_CLAIM_H
