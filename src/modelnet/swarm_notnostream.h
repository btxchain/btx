// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSTREAM_H
#define BTX_MODELNET_SWARM_NOTNOSTREAM_H

#include <string>

namespace modelnet {

/**
 * A local note about one engine. want_stream asks this note to treat the
 * note as a streamed token stream.
 *
 * A stream claim moves no tokens. streamed and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoStream {
    std::string engine_id;
    bool want_stream{false};
};

/**
 * Outcome of noting an engine stream request. streamed and bytes_moved
 * stay false on every path. A stream claim moves no tokens.
 */
struct SwarmNotNoStreamResult {
    std::string code;
    bool streamed{false};
    bool bytes_moved{false};
};

/**
 * Note an engine request without moving tokens. Order, first match wins:
 * an empty engine_id is ENGINE. want_stream is UNSTREAMED. Otherwise the
 * note is NOTED and err is cleared. streamed and bytes_moved stay false
 * on every path. A stream claim moves no tokens.
 */
SwarmNotNoStreamResult SwarmNoteNotNoStream(const SwarmNotNoStream& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSTREAM_H
