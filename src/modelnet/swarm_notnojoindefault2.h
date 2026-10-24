// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOJOINDEFAULT2_H
#define BTX_MODELNET_SWARM_NOTNOJOINDEFAULT2_H

#include <string>

namespace modelnet {

/**
 * A local note about join-on-acquire for one node. want_leave asks this
 * note to leave it.
 *
 * Join-on-acquire stays the ModelNet-on default. This note does not
 * leave it, so left stays false on every path.
 */
struct SwarmNotNoJoinDefault2 {
    std::string node_id;
    bool want_leave{false};
};

/**
 * Outcome of noting join-on-acquire. left stays false on every path:
 * this note does not leave it.
 */
struct SwarmNotNoJoinDefault2Result {
    std::string code;
    bool left{false};
};

/**
 * Note join-on-acquire without leaving it.
 * Order, first match wins: an empty node_id is NODE. want_leave is
 * HELD. Otherwise the note is NOTED and err is cleared. left stays
 * false on every path. Join-on-acquire stays the ModelNet-on default.
 */
SwarmNotNoJoinDefault2Result SwarmNoteNotNoJoinDefault2(const SwarmNotNoJoinDefault2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOJOINDEFAULT2_H
