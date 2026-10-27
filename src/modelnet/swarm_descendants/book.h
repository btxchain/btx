// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_BOOK_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_BOOK_H

#include <modelnet/swarm_descendants/node.h>

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Insertion-ordered descendant heads.
 *
 * AddBaseline rejects an empty id (LINEAGE) and a duplicate (REPLAY).
 * A baseline is its own head with an empty parent.
 * Fork rejects an unknown parent (PARENT), an empty child (LINEAGE),
 * and a child equal to that parent (SELF). A second fork of a stored
 * child is REPLAY and leaves the first parent in place.
 * A compatible child is stored under the parent and is not its own head.
 * An incompatible child is stored as its own head. The parent record
 * stays a head. err is FORK and the fork is kept.
 */
class DescendantBook {
public:
    bool AddBaseline(const std::string& id, std::string& err);
    bool Fork(const std::string& parent, const std::string& child, bool compatible, std::string& err);
    bool Assign(const std::string& child, const std::string& channel, std::string& err);

    bool contains(const std::string& id) const;
    std::size_t size() const { return m_order.size(); }

    SwarmDescendantNode* Find(const std::string& id);
    const SwarmDescendantNode* Find(const std::string& id) const;

    bool is_head(const std::string& id) const;
    std::string parent_of(const std::string& id) const;
    std::string head_of(const std::string& id) const;
    std::vector<std::string> on_head(const std::string& head) const;
    std::vector<std::string> heads() const;
    std::vector<std::string> heads(const std::string& channel) const;
    std::vector<std::string> channels(const std::string& id) const;

private:
    std::vector<std::string> m_order;
    std::map<std::string, SwarmDescendantNode> m_nodes;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_BOOK_H
