// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag06.h>

#include <string>

namespace modelnet {

SwarmFlag06Result SwarmStageTrain(const SwarmFlag06& in, std::string& err)
{
    SwarmFlag06Result result;
    result.paired = false;
    result.distributed = false;
    result.published = false;
    result.passed = false;
    result.bytes_moved = false;
    if (in.worker_a.empty() || in.worker_b.empty()) {
        result.code = "WORKER";
        result.paired = false;
        result.distributed = false;
        result.published = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "WORKER";
        return result;
    }
    if (in.worker_a == in.worker_b) {
        result.code = "SAME_WORKER";
        result.paired = false;
        result.distributed = false;
        result.published = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "SAME_WORKER";
        return result;
    }
    // Pairing is out of scope for this note. This wins even when a
    // checkpoint is missing or want_pass is set. Nothing is paired.
    if (in.want_pair) {
        result.code = "OUT_OF_SCOPE";
        result.paired = false;
        result.distributed = false;
        result.published = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "OUT_OF_SCOPE";
        return result;
    }
    if (!in.checkpoint_saved) {
        result.code = "NO_CHECKPOINT";
        result.paired = false;
        result.distributed = false;
        result.published = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "NO_CHECKPOINT";
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.paired = false;
        result.distributed = false;
        result.published = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.paired = false;
    result.distributed = false;
    result.published = false;
    result.passed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
