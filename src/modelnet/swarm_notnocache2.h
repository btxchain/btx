// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCACHE2_H
#define BTX_MODELNET_SWARM_NOTNOCACHE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one cache. want_share asks this note to share.
 *
 * A cache stands alone. Sharing it shares nothing and moves no bytes, so
 * shared stays false and bytes_moved stays false on every path.
 */
struct SwarmNotNoCache2 {
    std::string cache_id;
    bool want_share{false};
};

/**
 * Outcome of noting a cache. shared stays false and bytes_moved stays
 * false on every path. A cache stands alone.
 */
struct SwarmNotNoCache2Result {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a cache without sharing it or moving bytes.
 * Order, first match wins: an empty cache_id is CACHE. want_share is ALONE.
 * Otherwise the note is NOTED and err is cleared. shared stays false
 * and bytes_moved stays false on every path. A cache stands alone.
 */
SwarmNotNoCache2Result SwarmNoteNotNoCache2(const SwarmNotNoCache2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCACHE2_H
