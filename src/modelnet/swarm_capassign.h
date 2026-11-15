// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CAPASSIGN_H
#define BTX_MODELNET_SWARM_CAPASSIGN_H

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory assignment of a task to the earliest worker that lists a
 * required capability. Workers stay in the order AddWorker accepted them.
 *
 * AddWorker rejects an empty worker (WORKER) and a duplicate worker
 * (REPLAY). A new worker stores that capability set.
 *
 * Assign rejects an empty task or an empty required capability (TASK).
 * A second Assign of a task already stored is REPLAY and leaves that
 * worker in place. When no stored worker lists the required capability,
 * worker_out is empty, err is NOT_ACTED, and nothing is stored.
 * Otherwise the earliest added worker that lists the capability is stored
 * and written to worker_out.
 *
 * An uncovered capability assigns nobody. This record does not broadcast,
 * spend, spawn a child process, open a network connection, or record a
 * hostname or address.
 */
class SwarmCapAssign {
public:
    bool AddWorker(const std::string& worker, const std::vector<std::string>& capabilities, std::string& err);
    bool Assign(const std::string& task, const std::string& required, std::string& worker_out,
                std::string& err);
    std::string WorkerFor(const std::string& task) const;

private:
    std::vector<std::string> m_order;
    std::map<std::string, std::vector<std::string>> m_capabilities;
    std::map<std::string, std::string> m_assigned;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CAPASSIGN_H
