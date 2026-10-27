// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lineage.h>

#include <algorithm>
#include <string>

namespace modelnet {
namespace {

bool KnownChannel(const std::string& channel)
{
    return channel == "general" || channel == "coding" || channel == "research";
}

} // namespace

bool SwarmLineage::AddBaseline(const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = "MODEL";
        return false;
    }
    if (m_nodes.find(id) != m_nodes.end()) {
        err = "REPLAY";
        return false;
    }
    Node node;
    node.parent.clear();
    node.averaged = false;
    node.head = true;
    m_nodes.emplace(id, std::move(node));
    m_order.push_back(id);
    err.clear();
    return true;
}

bool SwarmLineage::Fork(const std::string& parent, const std::string& child, bool compatible, std::string& err)
{
    if (child.empty() || m_nodes.find(parent) == m_nodes.end()) {
        err = "MODEL";
        return false;
    }
    if (m_nodes.find(child) != m_nodes.end()) {
        err = "REPLAY";
        return false;
    }
    Node node;
    node.averaged = false;
    node.head = true;
    if (compatible) {
        node.parent = parent;
    } else {
        node.parent.clear();
    }
    m_nodes.emplace(child, std::move(node));
    m_order.push_back(child);
    // The parent record stays. An incompatible child is its own head.
    if (compatible) {
        err.clear();
    } else {
        err = "FORK";
    }
    return true;
}

bool SwarmLineage::Assign(const std::string& channel, const std::string& id, std::string& err)
{
    if (!KnownChannel(channel)) {
        err = "CHANNEL";
        return false;
    }
    const auto it = m_nodes.find(id);
    if (it == m_nodes.end()) {
        err = "MODEL";
        return false;
    }
    std::vector<std::string>& channels = it->second.channels;
    if (std::find(channels.begin(), channels.end(), channel) == channels.end()) {
        channels.push_back(channel);
    }
    err.clear();
    return true;
}

std::vector<std::string> SwarmLineage::Heads(const std::string& channel) const
{
    std::vector<std::string> heads;
    for (const std::string& id : m_order) {
        const auto it = m_nodes.find(id);
        if (it == m_nodes.end() || !it->second.head) {
            continue;
        }
        const std::vector<std::string>& channels = it->second.channels;
        if (std::find(channels.begin(), channels.end(), channel) != channels.end()) {
            heads.push_back(id);
        }
    }
    return heads;
}

bool SwarmLineage::Average(const std::string& left, const std::string& right, std::string& err)
{
    (void)left;
    (void)right;
    err = "NOT_AVERAGED";
    return false;
}

} // namespace modelnet
