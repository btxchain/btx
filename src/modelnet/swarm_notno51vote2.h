// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO51VOTE2_H
#define BTX_MODELNET_SWARM_NOTNO51VOTE2_H

#include <string>

namespace modelnet {

/**
 * A local note about a vote. majority is a 51 percent vote.
 * want_graduate asks this note to graduate a candidate.
 *
 * A 51 percent vote does not graduate and does not hide a head.
 * graduated and hidden stay false on every path.
 */
struct SwarmNotNo51Vote2 {
    std::string vote_id;
    bool majority{false};
    bool want_graduate{false};
};

/**
 * Outcome of noting a vote. graduated and hidden stay false on every path.
 * A 51 percent vote does not graduate and does not hide a head.
 */
struct SwarmNotNo51Vote2Result {
    std::string code;
    bool graduated{false};
    bool hidden{false};
};

/**
 * Note that a 51 percent vote does not graduate and does not hide a head.
 * Order, first match wins: an empty vote_id is VOTE. majority is
 * NOT_GRADUATED, even when want_graduate is false. want_graduate is HELD.
 * Otherwise the note is NOTED and err is clear. graduated and hidden stay
 * false on every path. A 51 percent vote does not graduate and does not
 * hide a head.
 */
SwarmNotNo51Vote2Result SwarmNoteNotNo51Vote2(const SwarmNotNo51Vote2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO51VOTE2_H
