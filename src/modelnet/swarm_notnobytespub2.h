// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBYTESPUB2_H
#define BTX_MODELNET_SWARM_NOTNOBYTESPUB2_H

#include <string>

namespace modelnet {

/**
 * A local note about one sample. want_publish asks this note to publish a
 * transferred-byte count.
 *
 * This note publishes no transferred-byte count and moves no bytes.
 * published stays false and bytes_moved stays false on every path.
 */
struct SwarmNotNoBytesPub2 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a transferred-byte request. published stays false and
 * bytes_moved stays false on every path. This note publishes no
 * transferred-byte count and moves no bytes.
 */
struct SwarmNotNoBytesPub2Result {
    std::string code;
    bool published{false};
    bool bytes_moved{false};
};

/**
 * Note a transferred-byte request without publishing a count or moving bytes.
 * Order, first match wins: an empty sample_id is SAMPLE.
 * want_publish is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * published stays false and bytes_moved stays false on every path.
 * This note publishes no transferred-byte count and moves no bytes.
 */
SwarmNotNoBytesPub2Result SwarmNoteNotNoBytesPub2(const SwarmNotNoBytesPub2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBYTESPUB2_H
