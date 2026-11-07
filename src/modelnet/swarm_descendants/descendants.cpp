// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_descendants/descendants.h>

#include <modelnet/swarm_descendants/average.h>
#include <modelnet/swarm_descendants/codes.h>
#include <modelnet/swarm_descendants/score.h>

namespace modelnet {

bool SwarmDescendants::AddBaseline(const std::string& id, std::string& err)
{
    return m_book.AddBaseline(id, err);
}

bool SwarmDescendants::Fork(const std::string& parent, const std::string& child, bool compatible, std::string& err)
{
    return m_book.Fork(parent, child, compatible, err);
}

bool SwarmDescendants::Average(std::string& err)
{
    return Average("", "", err);
}

bool SwarmDescendants::Average(const std::string& left, const std::string& right, std::string& err)
{
    // Refusal only. m_book is not updated, so every head stays where it is.
    return RefuseDescendantAverage(left, right, err);
}

bool SwarmDescendants::Assign(const std::string& child, const std::string& channel, std::string& err)
{
    return m_book.Assign(child, channel, err);
}

bool SwarmDescendants::Measure(const std::string& child, const std::string& author, bool independent, int64_t score, std::string& err)
{
    SwarmDescendantNode* node = m_book.Find(child);
    if (node == nullptr) {
        err = kDescendantLineage;
        return false;
    }
    return MeasureDescendant(*node, author, independent, score, err);
}

bool SwarmDescendants::accepted(const std::string& child) const
{
    const SwarmDescendantNode* node = m_book.Find(child);
    return node != nullptr && node->accepted;
}

std::vector<SwarmDescendantScore> SwarmDescendants::scores(const std::string& child) const
{
    const SwarmDescendantNode* node = m_book.Find(child);
    if (node == nullptr) return {};
    return node->scores;
}

} // namespace modelnet
