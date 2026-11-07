// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSTALEEP_H
#define BTX_MODELNET_SWARM_NOTNOSTALEEP_H

#include <string>

namespace modelnet {

/**
 * A local note about one lease. stale_epoch marks a lease from a stale
 * epoch. want_admit asks this note to admit a member.
 *
 * admitted and trained stay false on every path. A stale-epoch lease
 * admits no member and does not train.
 */
struct SwarmNotNoStaleEp {
    std::string lease_id;
    bool stale_epoch{false};
    bool want_admit{false};
};

/**
 * Outcome of noting a lease. admitted and trained stay false on every
 * path. A stale-epoch lease admits no member and does not train.
 */
struct SwarmNotNoStaleEpResult {
    std::string code;
    bool admitted{false};
    bool trained{false};
};

/**
 * Note a lease without admitting a member or training. Order, first
 * match wins: an empty lease_id is LEASE. stale_epoch is STALE_EPOCH
 * even when want_admit is false. want_admit is HELD. Otherwise the note
 * is NOTED and err is clear. admitted and trained stay false on every
 * path. A stale-epoch lease admits no member and does not train.
 */
SwarmNotNoStaleEpResult SwarmNoteNotNoStaleEp(const SwarmNotNoStaleEp& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSTALEEP_H
