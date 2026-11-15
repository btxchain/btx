// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBODY32_H
#define BTX_MODELNET_SWARM_NOTNOBODY32_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one body. want_store asks this note to store the body.
 *
 * The body cap is 32 MiB and this note stores nothing. stored and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoBody32 {
    std::string body_id;
    int64_t size_bytes{0};
    bool want_store{false};
};

/**
 * Outcome of noting a body. stored and bytes_moved stay false on every
 * path: this note stores nothing.
 */
struct SwarmNotNoBody32Result {
    std::string code;
    bool stored{false};
    bool bytes_moved{false};
};

/**
 * Note a body without storing it. Order, first match wins: an empty
 * body_id is BODY. size_bytes that is not exactly 33554432 is CAPPED
 * even when want_store is false. want_store is CAPPED. Otherwise the
 * note is NOTED and err is cleared. stored and bytes_moved stay false
 * on every path. The body cap is 32 MiB and this note stores nothing.
 */
SwarmNotNoBody32Result SwarmNoteNotNoBody32(const SwarmNotNoBody32& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBODY32_H
