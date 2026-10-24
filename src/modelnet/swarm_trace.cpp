// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_trace.h>

namespace modelnet {

bool SwarmTrace::Append(const std::string& task, const std::string& event, std::string& err)
{
    if (task.empty() || event.empty()) {
        err = "TRACE";
        return false;
    }
    rows_.push_back(Row{task, event});
    err.clear();
    return true;
}

std::vector<std::string> SwarmTrace::Events(const std::string& task) const
{
    std::vector<std::string> events;
    events.reserve(rows_.size());
    for (const Row& row : rows_) {
        if (row.task == task) {
            events.push_back(row.event);
        }
    }
    return events;
}

std::size_t SwarmTrace::size() const
{
    return rows_.size();
}

} // namespace modelnet
