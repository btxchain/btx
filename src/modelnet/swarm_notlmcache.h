// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTLMCACHE_H
#define BTX_MODELNET_SWARM_NOTLMCACHE_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. cuda_ops_present records whether compiled
 * LMCache CUDA ops are present. want_transfer asks this note to move KV bytes.
 *
 * Missing compiled LMCache CUDA ops is not a KV transfer.
 * bytes_moved stays false on every path.
 */
struct SwarmNotLmcache {
    std::string page_id;
    bool cuda_ops_present{false};
    bool want_transfer{false};
};

/**
 * Outcome of noting an LMCache request. bytes_moved stays false on every
 * path: missing compiled LMCache CUDA ops is not a KV transfer, and present
 * ops still move no bytes from this note.
 */
struct SwarmNotLmcacheResult {
    std::string code;
    bool bytes_moved{false};
};

/**
 * Note an LMCache request without moving KV bytes.
 * Order, first match wins: an empty page_id is CACHE.
 * Absent compiled CUDA ops is ENGINE_ABSENT, even when want_transfer is true.
 * want_transfer with ops present is HELD and err is clear.
 * Otherwise the note is NOTED and err is clear.
 * bytes_moved stays false on every path.
 */
SwarmNotLmcacheResult SwarmNoteNotLmcache(const SwarmNotLmcache& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTLMCACHE_H
