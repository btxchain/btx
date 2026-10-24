// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PIECE32_H
#define BTX_MODELNET_SWARM_PIECE32_H

#include <cstdint>
#include <string>

namespace modelnet {

/** One piece body is capped at 32 MiB. */
static constexpr int64_t SWARM_PIECE_BODY_CAP = 33554432;

/**
 * A local note about one piece body. piece_id names the piece. bytes is
 * the claimed body length. want_store asks this note to store the body.
 *
 * This note does not store a body and does not write bytes. accepted and
 * bytes_moved stay false on every path. No hostnames or IPs are used.
 */
struct SwarmPieceBody {
    std::string piece_id;
    int64_t bytes{0};
    bool want_store{false};
};

/**
 * Outcome of noting a piece body. accepted and bytes_moved stay false:
 * this note does not accept a store and does not move bytes.
 */
struct SwarmPieceBodyResult {
    bool accepted{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Note a piece body without storing it.
 * Order, first match wins:
 * an empty piece_id or bytes < 0 is PIECE.
 * bytes above 33554432 is OVERSIZE, including when want_store is true.
 * want_store is HELD and err is cleared. This note does not store a body.
 * Otherwise the note is NOTED and err is cleared. bytes == 33554432 with
 * want_store false is NOTED.
 * accepted and bytes_moved stay false. Nothing is written.
 */
SwarmPieceBodyResult SwarmNotePieceBody(const SwarmPieceBody& body, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PIECE32_H
