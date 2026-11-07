// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NOTCACHEOFF_H
#define BITCOIN_MODELNET_SWARM_NOTCACHEOFF_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one run. want_publish asks this note to publish a
 * comparison with cache sharing disabled.
 *
 * A comparison with cache sharing disabled has not been measured.
 * published stays false, delta stays 0, and bytes_moved stays false on
 * every path.
 */
struct SwarmNotCacheOff {
    std::string run_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a cache-sharing-disabled comparison. published stays
 * false, delta stays 0, and bytes_moved stays false: a comparison with
 * cache sharing disabled has not been measured.
 */
struct SwarmNotCacheOffResult {
    std::string code;
    bool published{false};
    int64_t delta{0};
    bool bytes_moved{false};
};

/**
 * Note a cache-sharing-disabled comparison without measuring it. Order,
 * first match wins: an empty run_id is RUN. want_publish is UNMEASURED.
 * Otherwise the note is NOTED and err is cleared. published stays false,
 * delta stays 0, and bytes_moved stays false on every path. A comparison
 * with cache sharing disabled has not been measured.
 */
SwarmNotCacheOffResult SwarmNoteNotCacheOff(const SwarmNotCacheOff& note, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NOTCACHEOFF_H
