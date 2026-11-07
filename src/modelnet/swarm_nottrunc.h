// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTRUNC_H
#define BTX_MODELNET_SWARM_NOTTRUNC_H

#include <string>

namespace modelnet {

/**
 * A local note that a page might accept a truncated or incompatible
 * transferred cache. want_accept asks this note to accept one.
 *
 * A truncated or incompatible transferred cache has not been shown on a live
 * tensor, so this note does not accept one and does not move bytes. accepted
 * and bytes_moved stay false on every path.
 */
struct SwarmNotTrunc {
    std::string page_id;
    bool want_accept{false};
};

/**
 * Outcome of noting an unshown truncated or incompatible transferred cache.
 * accepted and bytes_moved stay false on every path: a truncated or
 * incompatible transferred cache has not been shown on a live tensor.
 */
struct SwarmNotTruncResult {
    std::string code;
    bool accepted{false};
    bool bytes_moved{false};
};

/**
 * Note that no truncated or incompatible transferred cache is accepted and
 * no bytes are moved. Order, first match wins: an empty page_id is PAGE.
 * want_accept is NOT_SHOWN. Otherwise the note is NOTED and err is clear.
 * accepted and bytes_moved stay false on every path. A truncated or
 * incompatible transferred cache has not been shown on a live tensor.
 */
SwarmNotTruncResult SwarmNoteNotTrunc(const SwarmNotTrunc& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTRUNC_H
