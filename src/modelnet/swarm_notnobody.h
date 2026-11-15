// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBODY_H
#define BTX_MODELNET_SWARM_NOTNOBODY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one body. want_store asks this note to store the body.
 *
 * The body cap is 32 MiB and this note stores nothing. stored stays false
 * and applied_bytes stays 0 on every path.
 */
struct SwarmNotNoBody {
    std::string body_id;
    int64_t size_bytes{0};
    bool want_store{false};
};

/**
 * Outcome of noting a body. stored stays false and applied_bytes stays 0
 * on every path: this note stores nothing.
 */
struct SwarmNotNoBodyResult {
    std::string code;
    bool stored{false};
    int64_t applied_bytes{0};
};

/**
 * Note a body without storing it. Order, first match wins: an empty
 * body_id is BODY. size_bytes that is not exactly 33554432 is CAPPED
 * even when want_store is false. want_store is CAPPED. Otherwise the
 * note is NOTED and err is cleared. stored stays false and applied_bytes
 * stays 0 on every path. The body cap is 32 MiB and this note stores nothing.
 */
SwarmNotNoBodyResult SwarmNoteNotNoBody(const SwarmNotNoBody& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBODY_H
