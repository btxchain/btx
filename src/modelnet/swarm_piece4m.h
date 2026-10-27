// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PIECE4M_H
#define BTX_MODELNET_SWARM_PIECE4M_H

#include <cstdint>
#include <string>

namespace modelnet {

/** A manifest split uses pieces of 4 MiB. */
static constexpr int64_t SWARM_PIECE_SPLIT_BYTES = 4194304;

/**
 * A local note about one manifest piece split. manifest_id names the
 * manifest. piece_bytes is the claimed piece length. want_store asks this
 * note to store the piece.
 *
 * This note does not store a piece and does not write bytes. accepted and
 * bytes_moved stay false on every path. No hostnames or IPs are used.
 */
struct SwarmPieceSplit {
    std::string manifest_id;
    int64_t piece_bytes{0};
    bool want_store{false};
};

/**
 * Outcome of noting a manifest piece split. accepted and bytes_moved stay
 * false: this note does not accept a store and does not move bytes.
 */
struct SwarmPieceSplitResult {
    bool accepted{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Note a manifest piece split without storing it.
 * Order, first match wins:
 * an empty manifest_id or piece_bytes < 0 is PIECE.
 * piece_bytes above 4194304 is SPLIT_CAP, including when want_store is true.
 * want_store is HELD and err is cleared. This note does not store a piece.
 * Otherwise the note is NOTED and err is cleared. piece_bytes == 4194304
 * with want_store false is NOTED.
 * accepted and bytes_moved stay false. Nothing is written.
 */
SwarmPieceSplitResult SwarmNotePieceSplit(const SwarmPieceSplit& split, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PIECE4M_H
