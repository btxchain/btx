// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFALSECOMPAT_H
#define BTX_MODELNET_SWARM_NOTFALSECOMPAT_H

#include <string>

namespace modelnet {

/**
 * A local note about one discovery peer. want_share asks this note to treat
 * a peer advertising false compatibility as a live share.
 *
 * A discovery peer advertising false compatibility has not been shown as a
 * live share. shared and bytes_moved stay false on every path.
 */
struct SwarmNotFalseCompat {
    std::string peer_id;
    bool want_share{false};
};

/**
 * Outcome of noting a false-compatibility advertisement. shared and
 * bytes_moved stay false on every path: a discovery peer advertising false
 * compatibility has not been shown as a live share.
 */
struct SwarmNotFalseCompatResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a false-compatibility advertisement without showing it as a live share.
 * Order, first match wins: an empty peer_id is PEER. want_share is NOT_LIVE.
 * Otherwise the note is NOTED and err is clear.
 * shared and bytes_moved stay false on every path.
 */
SwarmNotFalseCompatResult SwarmNoteNotFalseCompat(const SwarmNotFalseCompat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFALSECOMPAT_H
