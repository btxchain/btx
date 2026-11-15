// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPREFETCH_H
#define BTX_MODELNET_SWARM_NOTPREFETCH_H

#include <string>

namespace modelnet {

/**
 * A local note about one page. engine_present records whether a prefetch
 * engine is present. want_prefetch asks this note to prefetch the page.
 *
 * Prefetch moves no bytes. prefetched and bytes_moved stay false on every
 * path.
 */
struct SwarmNotPrefetch {
    std::string page_id;
    bool want_prefetch{false};
    bool engine_present{false};
};

/**
 * Outcome of noting a prefetch request. prefetched and bytes_moved stay
 * false on every path: prefetch moves no bytes.
 */
struct SwarmNotPrefetchResult {
    std::string code;
    bool prefetched{false};
    bool bytes_moved{false};
};

/**
 * Note a prefetch request without moving bytes.
 * Order, first match wins: an empty page_id is PAGE.
 * Absent engine is ENGINE_ABSENT, even when want_prefetch is false.
 * want_prefetch is HELD, even when engine_present is true, and err is clear.
 * Otherwise the note is NOTED and err is clear.
 * prefetched and bytes_moved stay false on every path. Prefetch moves no bytes.
 */
SwarmNotPrefetchResult SwarmNoteNotPrefetch(const SwarmNotPrefetch& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPREFETCH_H
