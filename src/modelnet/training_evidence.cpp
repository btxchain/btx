// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/training_evidence.h>

#include <cstddef>
#include <queue>
#include <set>
#include <unordered_map>
#include <utility>

namespace modelnet {
namespace {

bool UsableEdge(const Interval& interval, uint64_t total)
{
    return interval.start_inclusive < interval.end_exclusive && interval.end_exclusive <= total;
}

} // namespace

bool FullReplayCoverage(uint64_t total,
                        const std::string& start_state,
                        const std::string& final_state,
                        const std::vector<Interval>& intervals)
{
    std::unordered_map<uint64_t, std::vector<size_t>> by_start;
    by_start.reserve(intervals.size());
    for (size_t i = 0; i < intervals.size(); ++i) {
        if (!UsableEdge(intervals[i], total)) continue;
        by_start[intervals[i].start_inclusive].push_back(i);
    }

    struct Node {
        uint64_t pos;
        std::string state;
    };
    std::queue<Node> pending;
    std::set<std::pair<uint64_t, std::string>> seen;
    pending.push(Node{0, start_state});
    seen.emplace(0, start_state);

    while (!pending.empty()) {
        Node cur = std::move(pending.front());
        pending.pop();
        if (cur.pos == total && cur.state == final_state) return true;
        if (cur.pos >= total) continue;
        const auto found = by_start.find(cur.pos);
        if (found == by_start.end()) continue;
        for (const size_t idx : found->second) {
            const Interval& interval = intervals[idx];
            if (interval.start_state != cur.state) continue;
            const std::pair<uint64_t, std::string> next{interval.end_exclusive, interval.end_state};
            if (!seen.insert(next).second) continue;
            pending.push(Node{next.first, next.second});
        }
    }
    return false;
}

bool AcceptInterval(const Interval& interval,
                    const std::string& frozen_rng,
                    const std::string& frozen_optimizer,
                    const std::string& frozen_data_cursor,
                    std::string& err)
{
    if (interval.profile != "EXACT_CHECKS") {
        err = "BTX035_PROFILE";
        return false;
    }
    if (interval.rng != frozen_rng || interval.optimizer != frozen_optimizer ||
        interval.data_cursor != frozen_data_cursor) {
        err = "BTX035_RNG";
        return false;
    }
    if (interval.ancestry.empty()) {
        err = "BTX035_ANCESTRY";
        return false;
    }
    err.clear();
    return true;
}

bool Independent(const Interval& interval)
{
    return !interval.publisher_only;
}

} // namespace modelnet
