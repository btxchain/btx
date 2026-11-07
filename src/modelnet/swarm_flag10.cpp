// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag10.h>

#include <string>

namespace modelnet {

SwarmFlag10Result SwarmStageAdopt(const SwarmFlag10& in, std::string& err)
{
    SwarmFlag10Result result;
    // A subscribed second node verifies and stages. Adoption does not
    // happen, the note does not pass, and no bytes move.
    result.adopted = false;
    result.rollback_kept = false;
    result.passed = false;
    result.bytes_moved = false;

    if (in.node_id.empty() || in.descendant_id.empty()) {
        result.code = "NODE";
        result.adopted = false;
        result.rollback_kept = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "NODE";
        return result;
    }
    if (in.previous_id.empty()) {
        result.code = "NO_ROLLBACK";
        result.adopted = false;
        result.rollback_kept = false;
        result.passed = false;
        result.bytes_moved = false;
        err = "NO_ROLLBACK";
        return result;
    }
    // The previous id stays. Requested adoption is not performed.
    if (in.want_adopt) {
        result.code = "NOT_ADOPTED";
        result.adopted = false;
        result.rollback_kept = true;
        result.passed = false;
        result.bytes_moved = false;
        err = "NOT_ADOPTED";
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.adopted = false;
        result.rollback_kept = true;
        result.passed = false;
        result.bytes_moved = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.adopted = false;
    result.rollback_kept = true;
    result.passed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
