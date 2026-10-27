// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFETCH_H
#define BTX_MODELNET_SWARM_NOTNOFETCH_H

#include <string>

namespace modelnet {

/**
 * A local note that a dependency might be fetched.
 * want_fetch asks this note to fetch one.
 *
 * This note fetches no dependency and moves no bytes. fetched and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoFetch {
    std::string dep_id;
    bool want_fetch{false};
};

/**
 * Outcome of noting that no dependency is fetched. fetched and bytes_moved
 * stay false on every path: this note fetches no dependency and moves no
 * bytes.
 */
struct SwarmNotNoFetchResult {
    std::string code;
    bool fetched{false};
    bool bytes_moved{false};
};

/**
 * Note that no dependency is fetched and no bytes are moved.
 * Order, first match wins: an empty dep_id is DEP. want_fetch is
 * NOT_FETCHED. Otherwise the note is NOTED and err is cleared.
 * fetched and bytes_moved stay false on every path. This note fetches no
 * dependency and moves no bytes.
 */
SwarmNotNoFetchResult SwarmNoteNotNoFetch(const SwarmNotNoFetch& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFETCH_H
