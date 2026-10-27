// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_LINEAGE_H
#define BTX_MODELNET_SWARM_LINEAGE_H

#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Model heads stored in insertion order.
 *
 * AddBaseline rejects an empty id (MODEL) and a duplicate (REPLAY).
 * A baseline is a head with an empty parent.
 * Fork rejects an unknown parent or an empty child (MODEL) and a
 * duplicate child (REPLAY). A compatible fork stores the child with
 * that parent. An incompatible fork stores the child as its own head
 * with an empty parent and averaged false, and sets err to FORK.
 * The parent stays stored as a head.
 * Assign records an id on general, coding, or research. The same id
 * may sit on more than one channel. Another channel keeps its id.
 * An unknown channel is CHANNEL. An unknown id is MODEL.
 * Heads lists that channel's heads in the order they were stored.
 * Average returns false with NOT_AVERAGED and leaves every head.
 */
class SwarmLineage {
public:
    bool AddBaseline(const std::string& id, std::string& err);
    bool Fork(const std::string& parent, const std::string& child, bool compatible, std::string& err);
    bool Assign(const std::string& channel, const std::string& id, std::string& err);
    std::vector<std::string> Heads(const std::string& channel) const;
    bool Average(const std::string& left, const std::string& right, std::string& err);

private:
    struct Node {
        std::string parent;
        bool averaged{false};
        bool head{true};
        std::vector<std::string> channels;
    };

    std::vector<std::string> m_order;
    std::map<std::string, Node> m_nodes;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_LINEAGE_H
