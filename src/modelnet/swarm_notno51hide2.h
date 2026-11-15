// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO51HIDE2_H
#define BTX_MODELNET_SWARM_NOTNO51HIDE2_H

#include <string>

namespace modelnet {

/**
 * A local note about one vote. majority is a 51 percent vote.
 * want_hide asks this note to hide a head.
 *
 * A 51 percent vote does not hide a head. hidden stays false on every path.
 */
struct SwarmNotNo51Hide2 {
    std::string vote_id;
    bool majority{false};
    bool want_hide{false};
};

/**
 * Outcome of noting a vote. hidden stays false on every path.
 * A 51 percent vote does not hide a head.
 */
struct SwarmNotNo51Hide2Result {
    std::string code;
    bool hidden{false};
};

/**
 * Note that a 51 percent vote does not hide a head. Order, first match wins:
 * an empty vote_id is VOTE. majority is NOT_HIDDEN, even when want_hide is
 * false. want_hide is HELD. Otherwise the note is NOTED and err is clear.
 * hidden stays false on every path.
 */
SwarmNotNo51Hide2Result SwarmNoteNotNo51Hide2(const SwarmNotNo51Hide2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO51HIDE2_H
