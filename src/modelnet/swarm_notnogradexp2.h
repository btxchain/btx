// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGRADEXP2_H
#define BTX_MODELNET_SWARM_NOTNOGRADEXP2_H

#include <string>

namespace modelnet {

/**
 * A local note that a gradient update might be exported.
 * gradient marks the update as a gradient. want_export asks this note
 * to export one.
 *
 * A gradient update is not exported. exported and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoGradExp2 {
    std::string update_id;
    bool gradient{false};
    bool want_export{false};
};

/**
 * Outcome of noting that a gradient update is not exported.
 * exported and bytes_moved stay false on every path.
 */
struct SwarmNotNoGradExp2Result {
    std::string code;
    bool exported{false};
    bool bytes_moved{false};
};

/**
 * Note that a gradient update is not exported.
 * Order, first match wins: an empty update_id is UPDATE. gradient true
 * is NOT_EXPORTED even when want_export is false. want_export is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * exported and bytes_moved stay false on every path. A gradient update
 * is not exported.
 */
SwarmNotNoGradExp2Result SwarmNoteNotNoGradExp2(const SwarmNotNoGradExp2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGRADEXP2_H
