// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNETBYTES_H
#define BTX_MODELNET_SWARM_NOTNETBYTES_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about net bytes for one peer. want_publish asks this note to
 * publish a measured byte count.
 *
 * This note does not publish a measurement or move bytes. published and
 * bytes_moved stay false, and nbytes stays 0, on every path.
 */
struct SwarmNotNetBytes {
    std::string peer_id;
    bool want_publish{false};
};

/**
 * Outcome of noting net bytes. published and bytes_moved stay false, and
 * nbytes stays 0, on every path.
 */
struct SwarmNotNetBytesResult {
    std::string code;
    bool published{false};
    bool bytes_moved{false};
    int64_t nbytes{0};
};

/**
 * Note net bytes without publishing a measurement or moving bytes.
 * Order, first match wins: an empty peer_id is PEER.
 * want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is clear.
 * published and bytes_moved stay false, and nbytes stays 0, on every path.
 */
SwarmNotNetBytesResult SwarmNoteNotNetBytes(const SwarmNotNetBytes& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNETBYTES_H
