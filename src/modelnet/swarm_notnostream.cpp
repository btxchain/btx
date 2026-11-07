// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostream.h>

#include <string>

namespace modelnet {

SwarmNotNoStreamResult SwarmNoteNotNoStream(const SwarmNotNoStream& note, std::string& err)
{
    SwarmNotNoStreamResult result;
    result.streamed = false;
    result.bytes_moved = false;
    // A stream claim moves no tokens.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.streamed = false;
        result.bytes_moved = false;
        err = "ENGINE";
        return result;
    }
    if (note.want_stream) {
        result.code = "UNSTREAMED";
        result.streamed = false;
        result.bytes_moved = false;
        err = "UNSTREAMED";
        return result;
    }
    result.code = "NOTED";
    result.streamed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
