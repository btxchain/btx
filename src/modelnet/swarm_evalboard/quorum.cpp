// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalboard/quorum.h>

#include <modelnet/swarm_evalboard/limits.h>

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {
namespace {

bool SpreadWithin(int64_t lo, int64_t hi)
{
    if (hi < lo) return false;
    const uint64_t spread = static_cast<uint64_t>(hi) - static_cast<uint64_t>(lo);
    return spread <= static_cast<uint64_t>(kSwarmEvalScoreSpread);
}

} // namespace

bool SwarmEvalAccepted(const std::vector<SwarmEvalReport>& rows)
{
    if (rows.size() < 2) return false;

    std::set<std::string> authors;
    std::set<std::string> domains;
    int64_t lo = rows.front().score;
    int64_t hi = lo;
    for (const SwarmEvalReport& row : rows) {
        authors.insert(row.author);
        domains.insert(row.domain);
        if (row.score < lo) lo = row.score;
        if (row.score > hi) hi = row.score;
    }
    if (authors.size() < 2) return false;
    if (domains.size() < 2) return false;
    return SpreadWithin(lo, hi);
}

} // namespace modelnet
