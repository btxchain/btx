// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag05.h>

#include <string>

namespace modelnet {

SwarmFlag05Result SwarmStageExperience(const SwarmFlag05& in, std::string& err)
{
    SwarmFlag05Result result;
    result.recorded = false;
    result.passed = false;
    result.bytes_moved = false;
    if (in.agent_id.empty() || in.task_id.empty()) {
        result.code = "AGENT";
        result.recorded = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "AGENT";
        return result;
    }
    // An authorized public or synthetic trajectory is required.
    // This wins even when want_record is set. Nothing is recorded.
    if (!in.authorized || !in.synthetic_or_public) {
        result.code = "UNAUTHORIZED";
        result.recorded = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "UNAUTHORIZED";
        return result;
    }
    if (in.want_record) {
        result.code = "NOT_RECORDED";
        result.recorded = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "NOT_RECORDED";
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.recorded = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.recorded = false;
    result.passed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
