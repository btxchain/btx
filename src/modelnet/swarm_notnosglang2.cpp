// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosglang2.h>

#include <string>

namespace modelnet {

SwarmNotNoSglang2Result SwarmNoteNotNoSglang2(const SwarmNotNoSglang2& note, std::string& err)
{
    SwarmNotNoSglang2Result result;
    result.streamed = false;
    result.tokens = 0;
    // SGLang has not streamed tokens. This note streams nothing.
    if (note.engine_id.empty()) {
        result.code = "ENGINE";
        result.streamed = false;
        result.tokens = 0;
        err = "ENGINE";
        return result;
    }
    if (note.want_stream) {
        result.code = "NOT_STREAMED";
        result.streamed = false;
        result.tokens = 0;
        err = "NOT_STREAMED";
        return result;
    }
    result.code = "NOTED";
    result.streamed = false;
    result.tokens = 0;
    err.clear();
    return result;
}

} // namespace modelnet
