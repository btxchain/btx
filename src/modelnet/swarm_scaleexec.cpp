// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_scaleexec.h>

namespace modelnet {

SwarmScaleExecResult SwarmExecuteTimescale(const std::string& scale, bool record_present, std::string& err)
{
    SwarmScaleExecResult result;
    result.executed = false;
    result.trained = false;
    result.bytes_moved = false;
    if (scale.empty()) {
        result.code = "TIMESCALE";
        err = "TIMESCALE";
        return result;
    }
    if (scale != "immediate" && scale != "short" && scale != "medium" && scale != "long") {
        result.code = "TIMESCALE";
        err = "TIMESCALE";
        return result;
    }
    if (!record_present) {
        result.code = "NOT_FOUND";
        err = "NOT_FOUND";
        return result;
    }
    if (scale == "medium" || scale == "long") {
        result.code = "TRAIN_ABSENT";
        err = "TRAIN_ABSENT";
        return result;
    }
    result.code = "RECORD_ONLY";
    err.clear();
    return result;
}

} // namespace modelnet
