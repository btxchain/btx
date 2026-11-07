// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_DAG_H
#define BTX_MODELNET_SWARM_AGENTS_DAG_H

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Insertion-ordered task DAG for the in-process agent plane.
 *
 * Add rejects an empty id (TASK), a duplicate id (REPLAY), an unknown
 * dependency (DEP), and a cycle, including a self-dependency (CYCLE).
 * Ready returns ids whose every dependency is committed and that are
 * not themselves committed or cancelled. A cancelled dependency blocks
 * its dependents: they are not Ready and they cannot be committed.
 * Commit stores one result hash. The same hash commits again. A
 * different hash is CONFLICT and the first hash stays.
 */
class SwarmAgentDag {
public:
    bool Add(const std::string& task, const std::vector<std::string>& deps, std::string& err);
    std::vector<std::string> Ready() const;
    bool Commit(const std::string& task, const std::string& hash, std::string& err);
    bool Cancel(const std::string& task, std::string& err);
    std::string CommittedHash(const std::string& task) const;

private:
    struct Node {
        std::vector<std::string> deps;
        bool committed{false};
        bool cancelled{false};
        std::string result_hash;
    };

    /** True when start reaches target along dependency edges. A node reaches itself. */
    bool Reaches(const std::string& start, const std::string& target) const;
    bool DepsCommitted(const Node& node) const;

    std::vector<std::string> m_order;
    std::map<std::string, Node> m_nodes;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_DAG_H
