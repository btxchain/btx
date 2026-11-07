// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSGLANG_H
#define BTX_MODELNET_SWARM_NOTSGLANG_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_stream asks this note to treat the
 * note as a streamed SGLang token stream.
 *
 * SGLang has not streamed tokens, so this note does not claim a stream.
 * streamed stays false on every path.
 */
struct SwarmNotSglang {
    std::string node_id;
    bool want_stream{false};
};

/**
 * Outcome of noting an SGLang stream request. streamed stays false on every
 * path: SGLang has not streamed tokens, so this note does not claim a stream.
 */
struct SwarmNotSglangResult {
    std::string code;
    bool streamed{false};
};

/**
 * Note an SGLang stream request without claiming a token stream.
 * Order, first match wins: an empty node_id is ENGINE.
 * want_stream is UNSTREAMED.
 * Otherwise the note is NOTED and err is clear.
 * streamed stays false on every path.
 */
SwarmNotSglangResult SwarmNoteNotSglang(const SwarmNotSglang& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSGLANG_H
