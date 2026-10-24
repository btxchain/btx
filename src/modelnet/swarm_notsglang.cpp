// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notsglang.h>

#include <string>

namespace modelnet {

SwarmNotSglangResult SwarmNoteNotSglang(const SwarmNotSglang& note, std::string& err)
{
    SwarmNotSglangResult result;
    result.streamed = false;
    // SGLang has not streamed tokens, so this note does not claim a stream.
    if (note.node_id.empty()) {
        result.code = "ENGINE";
        result.streamed = false;
        err = "ENGINE";
        return result;
    }
    if (note.want_stream) {
        result.code = "UNSTREAMED";
        result.streamed = false;
        err = "UNSTREAMED";
        return result;
    }
    result.code = "NOTED";
    result.streamed = false;
    err.clear();
    return result;
}

} // namespace modelnet
