// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOJOINON_H
#define BTX_MODELNET_SWARM_NOTNOJOINON_H

#include <string>

namespace modelnet {

/**
 * A local note about join-on-acquire for one node. want_disable asks this
 * note to disable it.
 *
 * Join-on-acquire stays the ModelNet-on default. This note does not
 * disable it, so disabled and joined stay false on every path.
 */
struct SwarmNotNoJoinOn {
    std::string node_id;
    bool want_disable{false};
};

/**
 * Outcome of noting join-on-acquire. disabled and joined stay false on
 * every path: this note does not disable it.
 */
struct SwarmNotNoJoinOnResult {
    std::string code;
    bool disabled{false};
    bool joined{false};
};

/**
 * Note join-on-acquire without disabling it.
 * Order, first match wins: an empty node_id is NODE. want_disable is
 * HELD. Otherwise the note is NOTED and err is cleared. disabled and
 * joined stay false on every path. Join-on-acquire stays the ModelNet-on
 * default. This note does not disable it.
 */
SwarmNotNoJoinOnResult SwarmNoteNotNoJoinOn(const SwarmNotNoJoinOn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOJOINON_H
