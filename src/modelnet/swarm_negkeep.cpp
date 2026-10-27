// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_negkeep.h>

#include <string>

namespace modelnet {

SwarmNegKeepResult SwarmKeepNegative(const SwarmNegKeep& result, std::string& err)
{
    SwarmNegKeepResult out;
    out.hidden = false;
    out.training = false;
    // A negative result stays recorded. This record does not hide it or start training.
    if (result.result_id.empty()) {
        out.code = "RESULT";
        out.hidden = false;
        out.training = false;
        out.kept = false;
        err = "RESULT";
        return out;
    }
    if (result.negative) {
        out.code = "KEPT";
        out.hidden = false;
        out.training = false;
        out.kept = true;
        err = "KEPT";
        return out;
    }
    if (result.want_hide || result.want_train) {
        out.code = "HELD";
        out.hidden = false;
        out.training = false;
        out.kept = true;
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    out.hidden = false;
    out.training = false;
    out.kept = true;
    err.clear();
    return out;
}

} // namespace modelnet
