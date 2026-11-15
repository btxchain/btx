// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_explore.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

constexpr int64_t kIllustrationSlots = 5;
constexpr int64_t kIllustrationPpm = 200000;
constexpr int64_t kIllustrationCandidates = 3;

bool KnownIllustration(const SwarmExplore& explore)
{
    return explore.slots == kIllustrationSlots &&
           explore.exploration_ppm == kIllustrationPpm &&
           explore.candidate_count == kIllustrationCandidates;
}

SwarmExploreResult Refuse(const std::string& code, std::string& err)
{
    SwarmExploreResult result;
    result.first = 0;
    result.second = 0;
    result.third = 0;
    result.assigned = false;
    result.code = code;
    err = code;
    return result;
}

SwarmExploreResult Record(const std::string& code, std::string& err)
{
    SwarmExploreResult result;
    result.first = 1;
    result.second = 2;
    result.third = 2;
    result.assigned = false;
    result.code = code;
    err.clear();
    return result;
}

} // namespace

SwarmExploreResult SwarmNoteExplore(const SwarmExplore& explore, std::string& err)
{
    if (explore.pool_id.empty() || explore.slots < 1 || explore.exploration_ppm < 0 ||
        explore.exploration_ppm > 1000000 || explore.candidate_count < 1) {
        return Refuse("EXPLORE", err);
    }
    // ILLUSTRATION wins even when want_assign is true. This note does
    // not invent a general allocator.
    if (!KnownIllustration(explore)) {
        return Refuse("ILLUSTRATION", err);
    }
    // Nothing is scheduled.
    if (explore.want_assign) {
        return Record("HELD", err);
    }
    return Record("NOTED", err);
}

} // namespace modelnet
