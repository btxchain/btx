// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSGLANG_H
#define BTX_MODELNET_SWARM_NOTNOSGLANG_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. want_stream asks this note to treat the
 * note as a streamed SGLang token stream.
 *
 * This note does not claim an SGLang token stream. streamed stays false
 * and tokens stays 0 on every path.
 */
struct SwarmNotNoSglang {
    std::string engine_id;
    bool want_stream{false};
};

/**
 * Outcome of noting an engine stream request. streamed stays false and
 * tokens stays 0 on every path. This note does not claim an SGLang token
 * stream.
 */
struct SwarmNotNoSglangResult {
    std::string code;
    bool streamed{false};
    int tokens{0};
};

/**
 * Note an engine request without claiming an SGLang token stream.
 * Order, first match wins: an empty engine_id is ENGINE. want_stream is
 * UNSTREAMED. Otherwise the note is NOTED and err is cleared.
 * streamed stays false and tokens stays 0 on every path.
 * This note does not claim an SGLang token stream.
 */
SwarmNotNoSglangResult SwarmNoteNotNoSglang(const SwarmNotNoSglang& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSGLANG_H
