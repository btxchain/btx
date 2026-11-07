// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTBYTES_H
#define BTX_MODELNET_SWARM_NOTBYTES_H

#include <string>

namespace modelnet {

/**
 * A local note that a page might publish a transferred-byte count.
 * want_publish asks this note to publish one.
 *
 * No transferred-byte count has been measured, so this note does not publish
 * one and does not move bytes. published and bytes_moved stay false on every
 * path.
 */
struct SwarmNotBytes {
    std::string page_id;
    bool want_publish{false};
};

/**
 * Outcome of noting an unmeasured transferred-byte count. published and
 * bytes_moved stay false on every path: no transferred-byte count has been
 * measured.
 */
struct SwarmNotBytesResult {
    std::string code;
    bool published{false};
    bool bytes_moved{false};
};

/**
 * Note that no transferred-byte count is published and no bytes are moved.
 * Order, first match wins: an empty page_id is BYTES. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is clear.
 * published and bytes_moved stay false on every path. No transferred-byte
 * count has been measured.
 */
SwarmNotBytesResult SwarmNoteNotBytes(const SwarmNotBytes& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTBYTES_H
