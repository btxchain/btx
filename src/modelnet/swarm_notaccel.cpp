// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notaccel.h>

namespace modelnet {

SwarmNotAccelResult SwarmNoteNotAccel(const SwarmNotAccel& note, std::string& err)
{
    SwarmNotAccelResult result;
    result.advertised = false;
    result.training = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.advertised = false;
        result.training = false;
        err = "NODE";
        return result;
    }
    // A platform must not advertise training it does not have.
    // want_train is refused even when gpu_present is true, because no training job is started here.
    if (!note.gpu_present || note.want_train) {
        result.code = "CPU_ONLY";
        result.advertised = false;
        result.training = false;
        err = "CPU_ONLY";
        return result;
    }
    result.code = "NOTED";
    result.advertised = false;
    result.training = false;
    err.clear();
    return result;
}

} // namespace modelnet
