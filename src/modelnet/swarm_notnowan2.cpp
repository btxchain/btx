// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowan2.h>

#include <string>

namespace modelnet {

SwarmNotNoWan2Result SwarmNoteNotNoWan2(const SwarmNotNoWan2& note, std::string& err)
{
    SwarmNotNoWan2Result result;
    result.averaged = false;
    result.bytes_moved = false;
    // A WAN average request averages nothing and moves no bytes.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.averaged = false;
        result.bytes_moved = false;
        err = "RUN";
        return result;
    }
    if (note.want_average) {
        result.code = "NOT_AVERAGED";
        result.averaged = false;
        result.bytes_moved = false;
        err = "NOT_AVERAGED";
        return result;
    }
    result.code = "NOTED";
    result.averaged = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
