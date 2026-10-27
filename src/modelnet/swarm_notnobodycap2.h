// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBODYCAP2_H
#define BTX_MODELNET_SWARM_NOTNOBODYCAP2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one body. want_raise asks this note to raise the body.
 *
 * A body stays capped at 33554432 bytes. raised stays false on every path.
 */
struct SwarmNotNoBodyCap2 {
    std::string body_id;
    bool want_raise{false};
};

/**
 * Outcome of noting a body. raised stays false and bytes stays 33554432
 * on every path. A body stays capped at 33554432 bytes.
 */
struct SwarmNotNoBodyCap2Result {
    std::string code;
    bool raised{false};
    int64_t bytes{33554432};
};

/**
 * Note a body without raising it. Order, first match wins: an empty
 * body_id is BODY. want_raise is HELD. Otherwise the note is NOTED and
 * err is cleared. raised stays false and bytes stays 33554432 on every
 * path. A body stays capped at 33554432 bytes.
 */
SwarmNotNoBodyCap2Result SwarmNoteNotNoBodyCap2(const SwarmNotNoBodyCap2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBODYCAP2_H
