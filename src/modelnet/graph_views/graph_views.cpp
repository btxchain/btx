// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/graph_views/graph_views.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

constexpr int kWhite = 0;
constexpr int kGray = 1;
constexpr int kBlack = 2;

bool KnownKind(const std::string& kind)
{
    return kind == "record" || kind == "dependency" || kind == "evidence" || kind == "replication";
}

} // namespace

bool GraphViews::Reaches(const std::string& start, const std::string& target) const
{
    if (start == target) {
        return true;
    }
    std::vector<std::string> stack;
    std::map<std::string, bool> seen;
    stack.push_back(start);
    while (!stack.empty()) {
        const std::string current = stack.back();
        stack.pop_back();
        if (!seen.emplace(current, true).second) {
            continue;
        }
        const auto node = m_nodes.find(current);
        if (node == m_nodes.end()) {
            continue;
        }
        for (const std::string& dest : node->second.out) {
            if (dest == target) {
                return true;
            }
            stack.push_back(dest);
        }
    }
    return false;
}

bool GraphViews::HasCycle() const
{
    std::map<std::string, int> color;
    for (const auto& row : m_nodes) {
        color.emplace(row.first, kWhite);
    }
    std::vector<std::string> stack;
    std::vector<std::size_t> next;
    for (const auto& row : m_nodes) {
        if (color[row.first] != kWhite) {
            continue;
        }
        color[row.first] = kGray;
        stack.push_back(row.first);
        next.push_back(0);
        while (!stack.empty()) {
            const std::size_t depth = stack.size() - 1;
            const std::string current = stack[depth];
            const auto node = m_nodes.find(current);
            if (node == m_nodes.end()) {
                color[current] = kBlack;
                stack.pop_back();
                next.pop_back();
                continue;
            }
            const std::vector<std::string>& outs = node->second.out;
            if (next[depth] >= outs.size()) {
                color[current] = kBlack;
                stack.pop_back();
                next.pop_back();
                continue;
            }
            const std::string dest = outs[next[depth]];
            next[depth] += 1;
            const auto seen = color.find(dest);
            if (seen == color.end()) {
                continue;
            }
            if (seen->second == kGray) {
                return true;
            }
            if (seen->second == kBlack) {
                continue;
            }
            color[dest] = kGray;
            stack.push_back(dest);
            next.push_back(0);
        }
    }
    return false;
}

bool GraphViews::Add(const std::string& id, const std::string& kind, std::string& err)
{
    if (id.empty()) {
        err = "FIELD";
        return false;
    }
    if (!KnownKind(kind)) {
        err = "KIND";
        return false;
    }
    if (m_nodes.find(id) != m_nodes.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    Node node;
    node.kind = kind;
    node.text = kind;
    node.history.push_back(node.text);
    m_nodes.emplace(id, std::move(node));
    err.clear();
    return true;
}

bool GraphViews::Link(const std::string& from, const std::string& to, std::string& err)
{
    if (from.empty() || to.empty()) {
        err = "FIELD";
        return false;
    }
    const auto from_it = m_nodes.find(from);
    const auto to_it = m_nodes.find(to);
    if (from_it == m_nodes.end() || to_it == m_nodes.end()) {
        err = "ABSENT";
        return false;
    }
    for (const std::string& dest : from_it->second.out) {
        if (dest == to) {
            err = NIFDT_REPLAY;
            return false;
        }
    }
    if (Reaches(to, from)) {
        err = "CYCLE";
        return false;
    }
    from_it->second.out.push_back(to);
    err.clear();
    return true;
}

bool GraphViews::Dispatch(std::string& err) const
{
    if (HasCycle()) {
        err = "CYCLE";
        return false;
    }
    err.clear();
    return true;
}

bool GraphViews::Retract(const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = "FIELD";
        return false;
    }
    const auto found = m_nodes.find(id);
    if (found == m_nodes.end()) {
        err = "ABSENT";
        return false;
    }
    if (found->second.kind != "evidence") {
        err = "KIND";
        return false;
    }
    if (found->second.retracted) {
        err = NIFDT_REPLAY;
        return false;
    }
    found->second.retracted = true;
    found->second.history.push_back("retracted");
    err.clear();
    return true;
}

std::string GraphViews::History(const std::string& id) const
{
    const auto found = m_nodes.find(id);
    if (found == m_nodes.end() || found->second.history.empty()) {
        return {};
    }
    return found->second.history.front();
}

bool GraphViews::View(const std::string& name, std::string& err)
{
    if (!KnownKind(name)) {
        err = "KIND";
        return false;
    }
    m_view = name;
    err.clear();
    return true;
}

int64_t GraphViews::Count() const
{
    int64_t n = static_cast<int64_t>(0);
    for (const auto& item : m_nodes) {
        if (!m_view.empty() && item.second.kind != m_view) {
            continue;
        }
        n += static_cast<int64_t>(1);
    }
    return n;
}

bool GraphViews::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool GraphViews::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool GraphViews::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool GraphViews::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool GraphViews::contains(const std::string& id) const
{
    return m_nodes.find(id) != m_nodes.end();
}

bool GraphViews::has_link(const std::string& from, const std::string& to) const
{
    const auto found = m_nodes.find(from);
    if (found == m_nodes.end()) {
        return false;
    }
    for (const std::string& dest : found->second.out) {
        if (dest == to) {
            return true;
        }
    }
    return false;
}

bool GraphViews::retracted(const std::string& id) const
{
    const auto found = m_nodes.find(id);
    if (found == m_nodes.end()) {
        return false;
    }
    return found->second.retracted;
}

} // namespace modelnet
