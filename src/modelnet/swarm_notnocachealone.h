// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCACHEALONE_H
#define BTX_MODELNET_SWARM_NOTNOCACHEALONE_H

#include <string>

namespace modelnet {

/**
 * A local note about one cache. coupled marks the cache coupled to another
 * store. want_share asks this note to share.
 *
 * A cache stands alone. Coupling it to another store shares nothing and
 * moves no bytes, so shared stays false and bytes_moved stays false on
 * every path.
 */
struct SwarmNotNoCacheAlone {
    std::string cache_id;
    bool coupled{false};
    bool want_share{false};
};

/**
 * Outcome of noting a cache. shared stays false and bytes_moved stays
 * false on every path. A cache stands alone. Coupling it to another store
 * shares nothing and moves no bytes.
 */
struct SwarmNotNoCacheAloneResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a cache without sharing it or moving bytes.
 * Order, first match wins: an empty cache_id is CACHE. coupled true is
 * STANDS_ALONE even when want_share is false. want_share is HELD.
 * Otherwise the note is NOTED and err is cleared. shared stays false
 * and bytes_moved stays false on every path. A cache stands alone.
 * Coupling it to another store shares nothing and moves no bytes.
 */
SwarmNotNoCacheAloneResult SwarmNoteNotNoCacheAlone(const SwarmNotNoCacheAlone& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCACHEALONE_H
