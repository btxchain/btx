// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag01.h>

#include <string>

namespace modelnet {

SwarmFlag01Result SwarmStageAcquire(const SwarmFlag01& in, std::string& err)
{
    SwarmFlag01Result result;
    // A local gate never passes, moves bytes, or broadcasts.
    result.passed = false;
    result.bytes_moved = false;
    result.broadcast = false;
    result.verified = false;
    result.staged = false;
    if (in.artifact_id.empty()) {
        result.code = "ARTIFACT";
        result.staged = false;
        result.verified = false;
        result.passed = false;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "ARTIFACT";
        return result;
    }
    if (in.hash_len != 32) {
        result.code = "HASH";
        result.staged = false;
        result.verified = false;
        result.passed = false;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "HASH";
        return result;
    }
    if (!in.license_open) {
        result.code = "LICENSE";
        result.staged = false;
        result.verified = false;
        result.passed = false;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "LICENSE";
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.staged = false;
        result.verified = false;
        result.passed = false;
        result.bytes_moved = false;
        result.broadcast = false;
        err = "UNQUALIFIED";
        return result;
    }
    // Hash length 32 and an open license are the recorded local preconditions.
    // Verification stays false. This does not claim a GPU host verified the artifact.
    result.code = "STAGED";
    result.staged = true;
    result.verified = false;
    result.passed = false;
    result.bytes_moved = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
