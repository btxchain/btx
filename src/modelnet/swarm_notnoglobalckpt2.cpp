// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoglobalckpt2.h>

#include <string>

namespace modelnet {

SwarmNotNoGlobalCkpt2Result SwarmNoteNotNoGlobalCkpt2(const SwarmNotNoGlobalCkpt2& note, std::string& err)
{
    SwarmNotNoGlobalCkpt2Result result;
    result.built = false;
    result.bytes_moved = false;
    // Island admission builds no global checkpoint.
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.built = false;
        result.bytes_moved = false;
        err = "RUN";
        return result;
    }
    if (note.want_build) {
        result.code = "HELD";
        result.built = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.built = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
