// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag07.h>

namespace modelnet {

SwarmFlag07Result SwarmStageEvolve(const SwarmFlag07& in, std::string& err)
{
    SwarmFlag07Result result;
    result.produced = false;
    result.passed = false;
    result.bytes_moved = false;
    if (in.parent_id.empty() || in.candidate_a.empty() || in.candidate_b.empty()) {
        result.code = "PARENT";
        result.produced = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "PARENT";
        return result;
    }
    if (in.candidate_a == in.candidate_b) {
        result.code = "SAME_CANDIDATE";
        result.produced = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "SAME_CANDIDATE";
        return result;
    }
    if (!in.different_strategy) {
        result.code = "SAME_STRATEGY";
        result.produced = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "SAME_STRATEGY";
        return result;
    }
    // Distinct names are not a real descendant. This wins even when want_pass is true.
    if (!in.from_real_run) {
        result.code = "NOT_EVOLVED";
        result.produced = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "NOT_EVOLVED";
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.produced = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "UNQUALIFIED";
        return result;
    }
    // Distinct names are not a real descendant.
    result.code = "NOTED";
    result.produced = false;
    result.passed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
