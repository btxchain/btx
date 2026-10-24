// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TASKDAG_H
#define BTX_MODELNET_SWARM_TASKDAG_H

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory task DAG stored in insertion order.
 *
 * Add rejects an empty id (TASK), a duplicate id (REPLAY), an unknown
 * dependency (DEP), and a cycle, including a self-dependency (CYCLE).
 * Ready returns ids whose every dependency is committed and that are not
 * themselves committed or cancelled. Commit stores one result hash and
 * accepts the same hash again; a different hash is CONFLICT and leaves the
 * first hash in place. Cancel marks a node so it is never Ready, and a
 * dependent of a cancelled node is not Ready.
 */
class SwarmTaskDag {
public:
    bool Add(const std::string& id, const std::vector<std::string>& deps, std::string& err);
    std::vector<std::string> Ready() const;
    bool Commit(const std::string& id, const std::string& result_hash, std::string& err);
    bool Cancel(const std::string& id, std::string& err);

private:
    struct Node {
        std::vector<std::string> deps;
        bool committed{false};
        bool cancelled{false};
        std::string result_hash;
    };

    /** True when start reaches target along stored dependency edges. A node reaches itself. */
    bool Reaches(const std::string& start, const std::string& target) const;

    std::vector<std::string> m_order;
    std::map<std::string, Node> m_nodes;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TASKDAG_H
