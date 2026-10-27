// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TRACE_H
#define BTX_MODELNET_SWARM_TRACE_H

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

/**
 * An append-only local trace of task events.
 * An empty task or an empty event is TRACE and is not stored.
 * A stored pair stays in append order. There is no delete and no edit
 * of an earlier row. This trace does not broadcast, spend, spawn a
 * child process, or use a network, hostname, or IP.
 */
class SwarmTrace {
public:
    bool Append(const std::string& task, const std::string& event, std::string& err);
    std::vector<std::string> Events(const std::string& task) const;
    std::size_t size() const;

private:
    struct Row {
        std::string task;
        std::string event;
    };
    std::vector<Row> rows_;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TRACE_H
