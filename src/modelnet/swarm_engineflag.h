// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ENGINEFLAG_H
#define BTX_MODELNET_SWARM_ENGINEFLAG_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one engine flag. engine_flag says the caller set an
 * engine flag. want_move asks this note to move bytes.
 *
 * An engine flag is not a transfer. It moves no bytes.
 */
struct SwarmEngineFlag {
    std::string engine_id;
    bool engine_flag{false};
    bool want_move{false};
};

/**
 * Outcome of noting an engine flag. moved stays false and bytes_moved stays
 * 0 on every path: an engine flag is not a transfer.
 */
struct SwarmEngineFlagResult {
    std::string code;
    bool moved{false};
    int64_t bytes_moved{0};
};

/**
 * Note an engine flag without moving bytes.
 * Order, first match wins: an empty engine_id is ENGINE. engine_flag true
 * is NOT_TRANSFER even when want_move is false. want_move is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * moved stays false and bytes_moved stays 0 on every path.
 */
SwarmEngineFlagResult SwarmNoteEngineFlag(const SwarmEngineFlag& engine, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ENGINEFLAG_H
