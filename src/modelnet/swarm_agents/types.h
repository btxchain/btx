// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_TYPES_H
#define BTX_MODELNET_SWARM_AGENTS_TYPES_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * What the caller asks the in-process plane to run.
 * The sandbox root is only a prefix when it ends with a slash.
 * network and host_interpreter are refusals. This request does not
 * name a child process, a socket, or a spend.
 */
struct SwarmAgentRunRequest {
    std::string task;
    std::string kind;
    bool network{false};
    bool host_interpreter{false};
    int64_t requested_threads{0};
    int64_t requested_mib{0};
    std::string sandbox_root;
    std::string path;
};

/**
 * Outcome of one builtin that passed the gate.
 * launched is always false: the builtin runs in the caller.
 * has_result is true only when a result was stored.
 */
struct SwarmAgentBuiltinResult {
    bool ran{false};
    bool launched{false};
    bool has_result{false};
    uint64_t step{0};
    std::string result_hash;
};

/** One append-only trace row. event is never empty in a stored row. */
struct SwarmAgentTraceRow {
    std::string task;
    std::string event;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_TYPES_H
