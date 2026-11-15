// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalrole2.h>

#include <string>

namespace modelnet {

SwarmNotNoEvalRole2Result SwarmNoteNotNoEvalRole2(const SwarmNotNoEvalRole2& note, std::string& err)
{
    // Without a device file the node stays an evaluator and does not train.
    SwarmNotNoEvalRole2Result result;
    result.training = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.training = false;
        err = "NODE";
        return result;
    }
    // no_device is EVALUATOR even when want_train is false.
    if (note.no_device) {
        result.code = "EVALUATOR";
        result.training = false;
        err = "EVALUATOR";
        return result;
    }
    if (note.want_train) {
        result.code = "HELD";
        result.training = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    err.clear();
    return result;
}

} // namespace modelnet
