// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBYTES_H
#define BTX_MODELNET_SWARM_NOTNOBYTES_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note that a transfer might publish a transferred-byte count.
 * want_publish asks this note to publish one.
 *
 * No transferred-byte count is published by this note. published stays false
 * and bytes stays 0 on every path.
 */
struct SwarmNotNoBytes {
    std::string transfer_id;
    bool want_publish{false};
};

/**
 * Outcome of noting that no transferred-byte count is published. published
 * stays false and bytes stays 0 on every path.
 */
struct SwarmNotNoBytesResult {
    std::string code;
    bool published{false};
    int64_t bytes{0};
};

/**
 * Note that no transferred-byte count is published by this note.
 * Order, first match wins: an empty transfer_id is TRANSFER. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published stays false and bytes stays 0 on every path.
 */
SwarmNotNoBytesResult SwarmNoteNotNoBytes(const SwarmNotNoBytes& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBYTES_H
