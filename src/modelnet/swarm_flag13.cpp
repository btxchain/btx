// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag13.h>

#include <string>

namespace modelnet {

SwarmFlag13Result SwarmStageRepeat(const SwarmFlag13& in, std::string& err)
{
    SwarmFlag13Result result;
    // One training run is not continuous evolution.
    result.repeated = false;
    result.produced = false;
    result.passed = false;
    if (in.parent_id.empty() || in.cycle_id.empty()) {
        result.code = "PARENT";
        result.repeated = false;
        result.produced = false;
        result.passed = false;
        err = "PARENT";
        return result;
    }
    if (!in.parent_graduated) {
        result.code = "NOT_GRADUATED";
        result.repeated = false;
        result.produced = false;
        result.passed = false;
        err = "NOT_GRADUATED";
        return result;
    }
    if (!in.second_cycle) {
        result.code = "FIRST_ONLY";
        result.repeated = false;
        result.produced = false;
        result.passed = false;
        err = "FIRST_ONLY";
        return result;
    }
    if (in.want_repeat) {
        result.code = "NOT_REPEATED";
        result.repeated = false;
        result.produced = false;
        result.passed = false;
        err = "NOT_REPEATED";
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.repeated = false;
        result.produced = false;
        result.passed = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.repeated = false;
    result.produced = false;
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
