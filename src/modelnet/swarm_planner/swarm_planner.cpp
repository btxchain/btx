// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_planner/swarm_planner.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {
namespace {

constexpr int kUnseen = 0;
constexpr int kOnStack = 1;
constexpr int kDone = 2;

} // namespace

bool SwarmPlanner::ParseView(const std::string& view, ViewKind& out) const
{
    if (view == kSwarmPlannerResource) {
        out = ViewKind::Resource;
        return true;
    }
    if (view == kSwarmPlannerWorkView) {
        out = ViewKind::Work;
        return true;
    }
    if (view == kSwarmPlannerTopology) {
        out = ViewKind::Topology;
        return true;
    }
    if (view == kSwarmPlannerEvidence) {
        out = ViewKind::Evidence;
        return true;
    }
    return false;
}

bool SwarmPlanner::Contains(ViewKind view, const std::string& id) const
{
    switch (view) {
    case ViewKind::Resource:
        return m_resource.find(id) != m_resource.end();
    case ViewKind::Work:
        return m_work.find(id) != m_work.end();
    case ViewKind::Topology:
        return m_topology.find(id) != m_topology.end();
    case ViewKind::Evidence:
        return m_evidence.find(id) != m_evidence.end();
    }
    return false;
}

bool SwarmPlanner::DependsOn(const std::string& start, const std::string& target) const
{
    if (start == target) {
        return true;
    }
    std::vector<std::string> stack;
    stack.push_back(start);
    std::map<std::string, bool> seen;
    while (!stack.empty()) {
        const std::string current = stack.back();
        stack.pop_back();
        if (!seen.emplace(current, true).second) {
            continue;
        }
        const auto found = m_work.find(current);
        if (found == m_work.end()) {
            continue;
        }
        for (const std::string& pred : found->second.predecessors) {
            if (pred == target) {
                return true;
            }
            stack.push_back(pred);
        }
    }
    return false;
}

bool SwarmPlanner::Admit(const std::string& view, const std::string& id, std::string& err)
{
    ViewKind kind;
    if (!ParseView(view, kind)) {
        err = kSwarmPlannerView;
        return false;
    }
    if (id.empty()) {
        err = kSwarmPlannerId;
        return false;
    }
    if (Contains(kind, id)) {
        err = kSwarmPlannerReplay;
        return false;
    }
    switch (kind) {
    case ViewKind::Resource:
        m_resource.insert(id);
        break;
    case ViewKind::Work:
        m_work.emplace(id, WorkRecord{});
        break;
    case ViewKind::Topology:
        m_topology.insert(id);
        break;
    case ViewKind::Evidence:
        m_evidence.emplace(id, EvidenceRecord{});
        break;
    }
    HistoryRecord row;
    row.view = view;
    row.id = id;
    row.retraction = false;
    m_history.push_back(row);
    err.clear();
    return true;
}

bool SwarmPlanner::Depend(const std::string& before, const std::string& after, std::string& err)
{
    const auto before_it = m_work.find(before);
    const auto after_it = m_work.find(after);
    if (before_it == m_work.end() || after_it == m_work.end()) {
        err = kSwarmPlannerWork;
        return false;
    }
    if (DependsOn(before, after)) {
        err = kSwarmPlannerCycle;
        return false;
    }
    WorkRecord& after_node = after_it->second;
    for (const std::string& pred : after_node.predecessors) {
        if (pred == before) {
            err = kSwarmPlannerReplay;
            return false;
        }
    }
    after_node.predecessors.push_back(before);
    err.clear();
    return true;
}

bool SwarmPlanner::Dispatch(const std::string& id, std::string& err) const
{
    if (m_work.find(id) == m_work.end()) {
        err = kSwarmPlannerWork;
        return false;
    }

    bool cycle = false;
    bool invalid = false;
    bool blocked = false;

    std::map<std::string, int> color;
    std::vector<std::string> stack;
    std::vector<std::size_t> next;
    color.emplace(id, kOnStack);
    stack.push_back(id);
    next.push_back(0);

    while (!stack.empty()) {
        const std::size_t depth = stack.size() - 1;
        const std::string current = stack[depth];
        const auto node = m_work.find(current);
        if (node == m_work.end()) {
            color[current] = kDone;
            stack.pop_back();
            next.pop_back();
            continue;
        }
        const std::vector<std::string>& preds = node->second.predecessors;
        if (next[depth] >= preds.size()) {
            color[current] = kDone;
            stack.pop_back();
            next.pop_back();
            continue;
        }
        const std::string pred = preds[next[depth]];
        next[depth] += 1;

        const auto seen = color.find(pred);
        const int state = seen == color.end() ? kUnseen : seen->second;
        if (state == kOnStack) {
            cycle = true;
            continue;
        }
        if (state == kDone) {
            continue;
        }

        const auto evidence = m_evidence.find(pred);
        if (evidence != m_evidence.end() && evidence->second.retracted) {
            invalid = true;
        }
        const auto pred_node = m_work.find(pred);
        if (pred_node == m_work.end() || !pred_node->second.finished) {
            blocked = true;
        }
        if (pred_node == m_work.end()) {
            color[pred] = kDone;
            continue;
        }
        color.emplace(pred, kOnStack);
        stack.push_back(pred);
        next.push_back(0);
    }

    if (cycle) {
        err = kSwarmPlannerCycle;
        return false;
    }
    if (invalid) {
        err = kSwarmPlannerInvalid;
        return false;
    }
    if (blocked) {
        err = kSwarmPlannerBlocked;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmPlanner::Finish(const std::string& id, std::string& err)
{
    const auto found = m_work.find(id);
    if (found == m_work.end()) {
        err = kSwarmPlannerWork;
        return false;
    }
    found->second.finished = true;
    err.clear();
    return true;
}

bool SwarmPlanner::Wake(const std::string& event_id, std::string& err)
{
    if (event_id.empty()) {
        err = kSwarmPlannerEvent;
        return false;
    }
    if (!m_events.insert(event_id).second) {
        err = kSwarmPlannerReplay;
        return false;
    }
    m_outbox.push_back(event_id);
    err.clear();
    return true;
}

uint64_t SwarmPlanner::CommitCursor()
{
    m_cursor = static_cast<uint64_t>(m_outbox.size());
    return m_cursor;
}

bool SwarmPlanner::Propose(int64_t epoch, const std::string& body, std::string& err)
{
    if (!m_proposed) {
        m_proposed = true;
        m_epoch = epoch;
        m_body = body;
        err.clear();
        return true;
    }
    if (epoch < m_epoch) {
        err = kSwarmPlannerStale;
        return false;
    }
    if (epoch == m_epoch) {
        err = kSwarmPlannerReplay;
        return false;
    }
    m_epoch = epoch;
    m_body = body;
    err.clear();
    return true;
}

bool SwarmPlanner::Quiesce(std::string& err)
{
    m_quiescent = true;
    err.clear();
    return true;
}

bool SwarmPlanner::Retract(const std::string& evidence_id, std::string& err)
{
    const auto found = m_evidence.find(evidence_id);
    if (found == m_evidence.end()) {
        err = kSwarmPlannerId;
        return false;
    }
    if (found->second.retracted) {
        err = kSwarmPlannerReplay;
        return false;
    }
    found->second.retracted = true;
    HistoryRecord row;
    row.view = kSwarmPlannerEvidence;
    row.id = evidence_id;
    row.retraction = true;
    m_history.push_back(row);
    err.clear();
    return true;
}

bool SwarmPlanner::Search(const std::string& view, const std::string& id, bool allowed, std::string& err) const
{
    if (!allowed) {
        err = kSwarmPlannerNotVisible;
        return false;
    }
    ViewKind kind;
    if (!ParseView(view, kind)) {
        err = kSwarmPlannerView;
        return false;
    }
    if (!Contains(kind, id)) {
        err = kSwarmPlannerNotVisible;
        return false;
    }
    if (kind == ViewKind::Evidence) {
        const auto found = m_evidence.find(id);
        if (found != m_evidence.end() && found->second.retracted) {
            err = kSwarmPlannerNotVisible;
            return false;
        }
    }
    err.clear();
    return true;
}

bool SwarmPlanner::admitted(const std::string& view, const std::string& id) const
{
    ViewKind kind;
    if (!ParseView(view, kind)) {
        return false;
    }
    return Contains(kind, id);
}

bool SwarmPlanner::finished(const std::string& id) const
{
    const auto found = m_work.find(id);
    if (found == m_work.end()) {
        return false;
    }
    return found->second.finished;
}

bool SwarmPlanner::retracted(const std::string& evidence_id) const
{
    const auto found = m_evidence.find(evidence_id);
    if (found == m_evidence.end()) {
        return false;
    }
    return found->second.retracted;
}

bool SwarmPlanner::quiescent() const
{
    return m_quiescent;
}

int64_t SwarmPlanner::history_count() const
{
    return static_cast<int64_t>(m_history.size());
}

int64_t SwarmPlanner::visible_count() const
{
    int64_t count = 0;
    count += static_cast<int64_t>(m_resource.size());
    count += static_cast<int64_t>(m_work.size());
    count += static_cast<int64_t>(m_topology.size());
    for (const auto& item : m_evidence) {
        if (!item.second.retracted) {
            count += 1;
        }
    }
    return count;
}

bool SwarmPlanner::proposed() const
{
    return m_proposed;
}

int64_t SwarmPlanner::epoch() const
{
    return m_epoch;
}

const std::string& SwarmPlanner::body() const
{
    return m_body;
}

uint64_t SwarmPlanner::cursor() const
{
    return m_cursor;
}

uint64_t SwarmPlanner::outbox_size() const
{
    return static_cast<uint64_t>(m_outbox.size());
}

bool SwarmPlanner::launched() const
{
    return kSwarmPlannerLaunched;
}

bool SwarmPlanner::gpu() const
{
    return kSwarmPlannerGpu;
}

bool SwarmPlanner::broadcast() const
{
    return kSwarmPlannerBroadcast;
}

std::string SwarmPlanner::automatic_spend() const
{
    return std::string{kSwarmPlannerAutomaticSpend};
}

int64_t SwarmPlanner::bytes_moved() const
{
    return kSwarmPlannerBytesMoved;
}

} // namespace modelnet
