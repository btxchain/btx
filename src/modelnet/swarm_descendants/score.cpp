// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_descendants/score.h>

#include <modelnet/swarm_descendants/codes.h>
#include <modelnet/swarm_descendants/limits.h>

namespace modelnet {
namespace {

bool SpreadWithin(int64_t lo, int64_t hi)
{
    if (hi < lo) return false;
    const uint64_t spread = static_cast<uint64_t>(hi) - static_cast<uint64_t>(lo);
    return spread <= static_cast<uint64_t>(kDescendantScoreSpread);
}

void RecomputeAccepted(SwarmDescendantNode& node)
{
    if (node.scores.size() < 2) {
        node.accepted = false;
        return;
    }
    int64_t lo = node.scores.front().score;
    int64_t hi = lo;
    for (const SwarmDescendantScore& row : node.scores) {
        if (row.score < lo) lo = row.score;
        if (row.score > hi) hi = row.score;
    }
    node.accepted = SpreadWithin(lo, hi);
}

} // namespace

bool MeasureDescendant(SwarmDescendantNode& node, const std::string& author, bool independent, int64_t score, std::string& err)
{
    if (author.empty() || author == node.id) {
        err = kDescendantNotScored;
        return false;
    }
    if (!independent) {
        err = kDescendantHeld;
        return false;
    }
    for (const SwarmDescendantScore& row : node.scores) {
        if (row.author == author) {
            err = kDescendantReplay;
            return false;
        }
    }
    const bool head_before = node.own_head;
    const std::string parent_before = node.parent;
    SwarmDescendantScore row;
    row.author = author;
    row.score = score;
    node.scores.push_back(std::move(row));
    RecomputeAccepted(node);
    node.own_head = head_before;
    node.parent = parent_before;
    err.clear();
    return true;
}

} // namespace modelnet
