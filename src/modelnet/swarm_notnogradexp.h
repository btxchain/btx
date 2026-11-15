// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOGRADEXP_H
#define BTX_MODELNET_SWARM_NOTNOGRADEXP_H

#include <string>

namespace modelnet {

/**
 * A local note that a gradient update might be exported.
 * want_export asks this note to export one.
 *
 * A gradient update is not exported. exported and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoGradExp {
    std::string update_id;
    bool want_export{false};
};

/**
 * Outcome of noting that a gradient update is not exported.
 * exported and bytes_moved stay false on every path.
 */
struct SwarmNotNoGradExpResult {
    std::string code;
    bool exported{false};
    bool bytes_moved{false};
};

/**
 * Note that a gradient update is not exported.
 * Order, first match wins: an empty update_id is UPDATE. want_export is
 * NOT_EXPORTED. Otherwise the note is NOTED and err is clear.
 * exported and bytes_moved stay false on every path. A gradient update
 * is not exported.
 */
SwarmNotNoGradExpResult SwarmNoteNotNoGradExp(const SwarmNotNoGradExp& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOGRADEXP_H
