// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOBODYCAP_H
#define BTX_MODELNET_SWARM_NOTNOBODYCAP_H

#include <string>

namespace modelnet {

/**
 * A local note about one body. want_accept asks this note to accept the body.
 *
 * A body over 32 MiB is not accepted and moves no bytes. accepted and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoBodyCap {
    std::string body_id;
    bool over_cap{false};
    bool want_accept{false};
};

/**
 * Outcome of noting a body. accepted and bytes_moved stay false on every
 * path. A body over 32 MiB is not accepted and moves no bytes.
 */
struct SwarmNotNoBodyCapResult {
    std::string code;
    bool accepted{false};
    bool bytes_moved{false};
};

/**
 * Note a body without accepting it. Order, first match wins: an empty
 * body_id is BODY. over_cap is CAPPED even when want_accept is false.
 * want_accept is CAPPED. Otherwise the note is NOTED and err is cleared.
 * accepted and bytes_moved stay false on every path. A body over 32 MiB
 * is not accepted and moves no bytes.
 */
SwarmNotNoBodyCapResult SwarmNoteNotNoBodyCap(const SwarmNotNoBodyCap& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOBODYCAP_H
