// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEGRESS_H
#define BTX_MODELNET_SWARM_NOTNOEGRESS_H

#include <string>

namespace modelnet {

/**
 * A local note about one peer. authorized records whether the peer may
 * receive. want_send asks this note to send.
 *
 * An unauthorized peer receives nothing. sent and bytes_moved stay false
 * on every path.
 */
struct SwarmNotNoEgress {
    std::string peer_id;
    bool authorized{false};
    bool want_send{false};
};

/**
 * Outcome of noting that nothing is sent. sent and bytes_moved stay
 * false on every path: an unauthorized peer receives nothing.
 */
struct SwarmNotNoEgressResult {
    std::string code;
    bool sent{false};
    bool bytes_moved{false};
};

/**
 * Note that an unauthorized peer receives nothing.
 * Order, first match wins: an empty peer_id is PEER. authorized false is
 * NOT_CONNECTED, even when want_send is false. want_send is HELD.
 * Otherwise the note is NOTED and err is cleared. sent and bytes_moved
 * stay false on every path. An unauthorized peer receives nothing.
 */
SwarmNotNoEgressResult SwarmNoteNotNoEgress(const SwarmNotNoEgress& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEGRESS_H
