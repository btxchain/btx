// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomixed2.h>

#include <string>

namespace modelnet {

SwarmNotNoMixed2Result SwarmNoteNotNoMixed2(const SwarmNotNoMixed2& note, std::string& err)
{
    SwarmNotNoMixed2Result result;
    result.ran = false;
    result.gpu = false;
    // Mixed precision does not run.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.ran = false;
        result.gpu = false;
        err = "RUN";
        return result;
    }
    if (note.want_run) {
        result.code = "NOT_RUN";
        result.ran = false;
        result.gpu = false;
        err = "NOT_RUN";
        return result;
    }
    result.code = "NOTED";
    result.ran = false;
    result.gpu = false;
    err.clear();
    return result;
}

} // namespace modelnet
