// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalcpu2.h>

#include <string>

namespace modelnet {

SwarmNotNoEvalCpu2Result SwarmNoteNotNoEvalCpu2(const SwarmNotNoEvalCpu2& note, std::string& err)
{
    // CPU evaluation stays the default. gpu stays false on every path.
    SwarmNotNoEvalCpu2Result result;
    result.gpu = false;
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.gpu = false;
        err = "NODE";
        return result;
    }
    if (note.want_gpu) {
        result.code = "HELD";
        result.gpu = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
