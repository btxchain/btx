// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NIXLABSENT_H
#define BTX_MODELNET_SWARM_NIXLABSENT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one engine. adapter_absent says the NIXL adapter is missing.
 * want_move asks this note to move bytes.
 *
 * A missing NIXL adapter moves no bytes.
 * moved stays false and bytes_moved stays 0 on every path.
 */
struct SwarmNixlAbsent {
    std::string engine_id;
    bool adapter_absent{false};
    bool want_move{false};
};

/**
 * Outcome of noting a missing NIXL adapter. moved stays false and
 * bytes_moved stays 0 on every path: a missing NIXL adapter moves no bytes.
 */
struct SwarmNixlAbsentResult {
    std::string code;
    bool moved{false};
    int64_t bytes_moved{0};
};

/**
 * Note a missing NIXL adapter without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE. adapter_absent true
 * is ENGINE_ABSENT even when want_move is false. want_move true is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved stays false and bytes_moved stays 0 on every path.
 * A missing NIXL adapter moves no bytes.
 */
SwarmNixlAbsentResult SwarmNoteNixlAbsent(const SwarmNixlAbsent& engine, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NIXLABSENT_H
