// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTBODY_H
#define BTX_MODELNET_SWARM_NOTBODY_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one body. want_store asks this note to store the body.
 *
 * The body cap is 32 MiB and this note does not store a body. stored and
 * bytes_moved stay false on every path.
 */
struct SwarmNotBody {
    std::string body_id;
    int64_t size_bytes{0};
    bool want_store{false};
};

/**
 * Outcome of noting a body. stored and bytes_moved stay false on every path:
 * this note does not store a body.
 */
struct SwarmNotBodyResult {
    std::string code;
    bool stored{false};
    bool bytes_moved{false};
};

/**
 * Note a body without storing it. Order, first match wins: an empty body_id
 * is BODY. size_bytes above 33554432 (32 MiB) or want_store is CAPPED.
 * Otherwise the note is NOTED and err is cleared. stored and bytes_moved
 * stay false on every path. The body cap is 32 MiB and this note does not
 * store a body.
 */
SwarmNotBodyResult SwarmNoteNotBody(const SwarmNotBody& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTBODY_H
