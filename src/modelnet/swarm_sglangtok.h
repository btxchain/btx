// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SGLANGTOK_H
#define BTX_MODELNET_SWARM_SGLANGTOK_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one engine. engine_absent says the engine is missing.
 * want_stream asks this note to treat the note as a streamed SGLang token
 * stream.
 *
 * SGLang has not streamed tokens. A stream request moves no tokens.
 * streamed stays false and tokens stays 0 on every path.
 */
struct SwarmSglangTok {
    std::string engine_id;
    bool engine_absent{false};
    bool want_stream{false};
};

/**
 * Outcome of noting an SGLang stream request. streamed stays false and
 * tokens stays 0 on every path. SGLang has not streamed tokens. A stream
 * request moves no tokens.
 */
struct SwarmSglangTokResult {
    std::string code;
    bool streamed{false};
    int64_t tokens{0};
};

/**
 * Note an SGLang stream request without moving tokens.
 * Order, first match wins: an empty engine_id is ENGINE. engine_absent
 * true is ENGINE_ABSENT even when want_stream is false. want_stream is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * streamed stays false and tokens stays 0 on every path.
 * SGLang has not streamed tokens.
 */
SwarmSglangTokResult SwarmNoteSglangTok(const SwarmSglangTok& engine, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SGLANGTOK_H
