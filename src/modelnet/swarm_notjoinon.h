// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTJOINON_H
#define BTX_MODELNET_SWARM_NOTJOINON_H

#include <string>

namespace modelnet {

/**
 * A local note about join-on-acquire for one node.
 * Join-on-acquire is the ModelNet-on default.
 * want_skip_join asks this note to skip the join.
 *
 * This note does not join a peer or skip the join, so skipped and joined
 * stay false on every path.
 */
struct SwarmNotJoinOn {
    std::string node_id;
    bool modelnet_on{true};
    bool want_skip_join{false};
};

/**
 * Outcome of noting join-on-acquire. skipped and joined stay false on every
 * path: this note does not join a peer or skip the join.
 */
struct SwarmNotJoinOnResult {
    std::string code;
    bool skipped{false};
    bool joined{false};
};

/**
 * Note join-on-acquire without joining a peer or skipping the join.
 * Order, first match wins: an empty node_id is NODE. If modelnet_on is
 * false, the note is DEFAULT_ON even when want_skip_join is false.
 * want_skip_join is HELD. Otherwise the note is NOTED and err is clear.
 * skipped and joined stay false on every path. Join-on-acquire is the
 * ModelNet-on default. This note does not join a peer or skip the join.
 */
SwarmNotJoinOnResult SwarmNoteNotJoinOn(const SwarmNotJoinOn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTJOINON_H
