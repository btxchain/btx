// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosglang.h>

#include <string>

namespace modelnet {

SwarmNotNoSglangResult SwarmNoteNotNoSglang(const SwarmNotNoSglang& note, std::string& err)
{
    SwarmNotNoSglangResult result;
    result.streamed = false;
    result.tokens = 0;
    // This note does not claim an SGLang token stream.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.streamed = false;
        result.tokens = 0;
        err = "ENGINE";
        return result;
    }
    if (note.want_stream) {
        result.code = "UNSTREAMED";
        result.streamed = false;
        result.tokens = 0;
        err = "UNSTREAMED";
        return result;
    }
    result.code = "NOTED";
    result.streamed = false;
    result.tokens = 0;
    err.clear();
    return result;
}

} // namespace modelnet
