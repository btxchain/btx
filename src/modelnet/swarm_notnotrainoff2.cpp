// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrainoff2.h>

namespace modelnet {

SwarmNotNoTrainOff2Result SwarmNoteNotNoTrainOff2(const SwarmNotNoTrainOff2& note, std::string& err)
{
    // Training stays off.
    SwarmNotNoTrainOff2Result result;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.training = false;
        result.gpu = false;
        err = "NODE";
        return result;
    }
    if (note.want_train) {
        result.code = "HELD";
        result.training = false;
        result.gpu = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.training = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
