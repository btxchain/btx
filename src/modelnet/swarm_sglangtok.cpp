// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sglangtok.h>

#include <string>

namespace modelnet {

SwarmSglangTokResult SwarmNoteSglangTok(const SwarmSglangTok& engine, std::string& err)
{
    SwarmSglangTokResult result;
    result.streamed = false;
    result.tokens = 0;
    // SGLang has not streamed tokens.
    if (engine.engine_id.empty()) {
        result.code = "ENGINE";
        result.streamed = false;
        result.tokens = 0;
        err = "ENGINE";
        return result;
    }
    if (engine.engine_absent) {
        result.code = "ENGINE_ABSENT";
        result.streamed = false;
        result.tokens = 0;
        err = "ENGINE_ABSENT";
        return result;
    }
    if (engine.want_stream) {
        result.code = "HELD";
        result.streamed = false;
        result.tokens = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.streamed = false;
    result.tokens = 0;
    err.clear();
    return result;
}

} // namespace modelnet
