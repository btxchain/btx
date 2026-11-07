// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOJOIN_H
#define BTX_MODELNET_SWARM_NOTNOJOIN_H

#include <string>

namespace modelnet {

/**
 * A local note about join-on-acquire for one node. modelnet_on records
 * whether ModelNet is on. want_skip asks this note to skip.
 *
 * Join-on-acquire stays the ModelNet-on default, and this note skips
 * nothing, so skipped and joined stay false on every path.
 */
struct SwarmNotNoJoin {
    std::string node_id;
    bool modelnet_on{false};
    bool want_skip{false};
};

/**
 * Outcome of noting join-on-acquire. skipped and joined stay false on
 * every path: this note skips nothing.
 */
struct SwarmNotNoJoinResult {
    std::string code;
    bool skipped{false};
    bool joined{false};
};

/**
 * Note join-on-acquire without skipping it.
 * Order, first match wins: an empty node_id is NODE. If modelnet_on is
 * true, the note is HELD even when want_skip is false. want_skip is
 * HELD. Otherwise the note is NOTED and err is cleared. skipped and
 * joined stay false on every path. Join-on-acquire stays the ModelNet-on
 * default, and this note skips nothing.
 */
SwarmNotNoJoinResult SwarmNoteNotNoJoin(const SwarmNotNoJoin& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOJOIN_H
