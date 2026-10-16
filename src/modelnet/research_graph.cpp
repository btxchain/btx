// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_graph.h>

#include <modelnet/crypto.h>
#include <span.h>

namespace modelnet {
namespace {

bool SameBody(const ResearchContribution& stored, const Digest48& author_id, bool negative, std::string_view summary)
{
    return stored.author_id == author_id && stored.negative == negative && stored.summary == summary;
}

} // namespace

bool RejectCanonical(std::string_view label, std::string& err)
{
    const bool edged_space = !label.empty() && (label.front() == ' ' || label.back() == ' ');
    bool upper = false;
    for (char ch : label) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c >= 'A' && c <= 'Z') {
            upper = true;
            break;
        }
    }
    if (edged_space || upper) {
        err = "BTX035_TOPIC";
        return false;
    }
    err.clear();
    return true;
}

bool TopicId(std::string_view label, Digest48& out, std::string& err)
{
    if (label.empty()) {
        err = "BTX035_TOPIC";
        return false;
    }
    if (!RejectCanonical(label, err)) return false;
    out = DomainHash(RESEARCH_TOPIC_DOMAIN, Span<const unsigned char>{UCharCast(label.data()), label.size()});
    err.clear();
    return true;
}

bool ResearchBook::Publish(const Digest48& topic, const Digest48& contribution_id, const Digest48& author_id,
                           bool negative, std::string_view summary, std::string& err)
{
    auto& index = m_by_topic[topic];
    const auto it = index.find(contribution_id);
    if (it != index.end()) {
        if (!SameBody(it->second, author_id, negative, summary)) {
            err = "BTX035_CONFLICT";
            return false;
        }
        m_peers.insert(author_id);
        err.clear();
        return true;
    }
    ResearchContribution row;
    row.topic = topic;
    row.contribution_id = contribution_id;
    row.author_id = author_id;
    row.negative = negative;
    row.summary = std::string{summary};
    index.emplace(contribution_id, std::move(row));
    m_peers.insert(author_id);
    err.clear();
    return true;
}

bool ResearchBook::Find(const Digest48& topic, const Digest48& contribution_id, ResearchContribution& out) const
{
    const auto topic_it = m_by_topic.find(topic);
    if (topic_it == m_by_topic.end()) {
        out = {};
        return false;
    }
    const auto it = topic_it->second.find(contribution_id);
    if (it == topic_it->second.end()) {
        out = {};
        return false;
    }
    out = it->second;
    return true;
}

bool ResearchBook::AdoptSuccessor(const Digest48& parent_agent, const Digest48& child_agent,
                                  std::string_view parent_grant, std::string_view child_grant,
                                  const std::vector<Digest48>& memory_ids, std::string& err)
{
    // parent_agent names the lineage being left. The child stores memory_ids
    // under child_grant and does not receive the parent grant.
    (void)parent_agent;
    if (parent_grant.empty() || child_grant.empty() || parent_grant == child_grant) {
        err = "BTX035_GRANT";
        return false;
    }
    m_memory[child_agent] = memory_ids;
    err.clear();
    return true;
}

std::vector<Digest48> ResearchBook::MemoryOf(const Digest48& child_agent) const
{
    const auto it = m_memory.find(child_agent);
    if (it == m_memory.end()) return {};
    return it->second;
}

void ResearchBook::ContinueWithout(const Digest48& author_id)
{
    m_peers.erase(author_id);
}

bool ResearchBook::HasPeer(const Digest48& author_id) const
{
    return m_peers.find(author_id) != m_peers.end();
}

bool ResearchBook::Page(const Digest48& topic, const Digest48& cursor, size_t limit, ResearchPage& out, std::string& err) const
{
    out = {};
    if (limit == 0 || limit > RESEARCH_PAGE_MAX) {
        err = "BTX035_PAGE";
        return false;
    }
    err.clear();
    const auto topic_it = m_by_topic.find(topic);
    if (topic_it == m_by_topic.end()) return true;

    const auto& rows = topic_it->second;
    auto it = cursor.IsNull() ? rows.begin() : rows.upper_bound(cursor);
    while (it != rows.end() && out.rows.size() < limit) {
        out.rows.push_back(it->second);
        ++it;
    }
    if (it != rows.end() && !out.rows.empty()) {
        out.next_cursor = out.rows.back().contribution_id;
    }
    return true;
}

} // namespace modelnet
