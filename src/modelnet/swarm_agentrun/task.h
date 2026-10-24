// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_TASK_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_TASK_H

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

class SwarmAgentRunTrace;

/**
 * One node in the in-memory task forest.
 * parent is empty for a root. children lists direct children in insert order.
 * cancelled stays false until Cancel stores that state. A cancel does not
 * erase the node, its parent, its children, or any result stored elsewhere.
 */
struct SwarmAgentRunTask {
    std::string parent;
    std::string capability;
    bool cancelled{false};
    std::vector<std::string> children;
};

/**
 * Task forest.
 * Empty id is TASK. A non-empty parent that is not already a task is
 * DEPENDENCY and stores nothing, even when the id is already present.
 * An empty parent is a root. A duplicate id whose parent is empty or
 * already a task is REPLAY and keeps the first parent and capability.
 * Cancel sets the cancelled flag and leaves the node in place.
 * A second cancel is REPLAY.
 */
class SwarmAgentRunTasks {
public:
    bool Add(const std::string& id, const std::string& parent, const std::string& capability, SwarmAgentRunTrace& trace, std::string& err);
    bool Cancel(const std::string& id, SwarmAgentRunTrace& trace, std::string& err);

    bool contains(const std::string& id) const;
    std::size_t count() const;
    std::string parent_of(const std::string& id) const;
    std::string capability_of(const std::string& id) const;
    std::vector<std::string> children_of(const std::string& id) const;
    bool cancelled(const std::string& id) const;

private:
    std::map<std::string, SwarmAgentRunTask> m_tasks;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_TASK_H
