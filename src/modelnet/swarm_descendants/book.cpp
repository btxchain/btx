// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_descendants/book.h>

#include <modelnet/swarm_descendants/codes.h>
#include <modelnet/swarm_descendants/niche.h>

#include <algorithm>

namespace modelnet {

bool DescendantBook::AddBaseline(const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = kDescendantLineage;
        return false;
    }
    if (m_nodes.find(id) != m_nodes.end()) {
        err = kDescendantReplay;
        return false;
    }
    SwarmDescendantNode node;
    node.id = id;
    node.parent.clear();
    node.own_head = true;
    m_nodes.emplace(id, std::move(node));
    m_order.push_back(id);
    err.clear();
    return true;
}

bool DescendantBook::Fork(const std::string& parent, const std::string& child, bool compatible, std::string& err)
{
    if (m_nodes.find(parent) == m_nodes.end()) {
        err = kDescendantParent;
        return false;
    }
    if (child.empty()) {
        err = kDescendantLineage;
        return false;
    }
    if (child == parent) {
        err = kDescendantSelf;
        return false;
    }
    if (m_nodes.find(child) != m_nodes.end()) {
        err = kDescendantReplay;
        return false;
    }
    SwarmDescendantNode node;
    node.id = child;
    node.parent = parent;
    // Compatible work stays on the parent head. An incompatible child
    // competes as its own head. The parent node is not rewritten.
    node.own_head = !compatible;
    m_nodes.emplace(child, std::move(node));
    m_order.push_back(child);
    if (compatible) {
        err.clear();
    } else {
        err = kDescendantFork;
    }
    return true;
}

bool DescendantBook::Assign(const std::string& child, const std::string& channel, std::string& err)
{
    const auto it = m_nodes.find(child);
    if (child.empty() || it == m_nodes.end()) {
        err = kDescendantLineage;
        return false;
    }
    if (!DescendantNicheKnown(channel)) {
        err = kDescendantNiche;
        return false;
    }
    std::vector<std::string>& channels = it->second.channels;
    if (std::find(channels.begin(), channels.end(), channel) == channels.end()) {
        channels.push_back(channel);
    }
    err.clear();
    return true;
}

bool DescendantBook::contains(const std::string& id) const
{
    return m_nodes.find(id) != m_nodes.end();
}

SwarmDescendantNode* DescendantBook::Find(const std::string& id)
{
    const auto it = m_nodes.find(id);
    if (it == m_nodes.end()) return nullptr;
    return &it->second;
}

const SwarmDescendantNode* DescendantBook::Find(const std::string& id) const
{
    const auto it = m_nodes.find(id);
    if (it == m_nodes.end()) return nullptr;
    return &it->second;
}

bool DescendantBook::is_head(const std::string& id) const
{
    const SwarmDescendantNode* node = Find(id);
    return node != nullptr && node->own_head;
}

std::string DescendantBook::parent_of(const std::string& id) const
{
    const SwarmDescendantNode* node = Find(id);
    if (node == nullptr) return {};
    return node->parent;
}

std::string DescendantBook::head_of(const std::string& id) const
{
    std::string current = id;
    for (std::size_t guard = 0; guard < m_order.size(); ++guard) {
        const SwarmDescendantNode* node = Find(current);
        if (node == nullptr) return {};
        if (node->own_head) return current;
        if (node->parent.empty() || node->parent == current) return {};
        current = node->parent;
    }
    return {};
}

std::vector<std::string> DescendantBook::on_head(const std::string& head) const
{
    std::vector<std::string> ids;
    if (head.empty() || !is_head(head)) return ids;
    for (const std::string& id : m_order) {
        if (head_of(id) == head) ids.push_back(id);
    }
    return ids;
}

std::vector<std::string> DescendantBook::heads() const
{
    std::vector<std::string> ids;
    for (const std::string& id : m_order) {
        if (is_head(id)) ids.push_back(id);
    }
    return ids;
}

std::vector<std::string> DescendantBook::heads(const std::string& channel) const
{
    std::vector<std::string> ids;
    for (const std::string& id : m_order) {
        const SwarmDescendantNode* node = Find(id);
        if (node == nullptr || !node->own_head) continue;
        const std::vector<std::string>& channels = node->channels;
        if (std::find(channels.begin(), channels.end(), channel) != channels.end()) {
            ids.push_back(id);
        }
    }
    return ids;
}

std::vector<std::string> DescendantBook::channels(const std::string& id) const
{
    const SwarmDescendantNode* node = Find(id);
    if (node == nullptr) return {};
    return node->channels;
}

} // namespace modelnet
