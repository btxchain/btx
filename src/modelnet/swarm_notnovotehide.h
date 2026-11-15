// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOVOTEHIDE_H
#define BTX_MODELNET_SWARM_NOTNOVOTEHIDE_H

#include <string>

namespace modelnet {

/**
 * A local note about a vote on one chain. majority is a 51 percent vote.
 * want_hide asks this note to hide a head.
 *
 * A 51 percent vote does not hide a head and does not graduate a candidate.
 * hidden and graduated stay false on every path.
 */
struct SwarmNotNoVoteHide {
    std::string chain_id;
    bool majority{false};
    bool want_hide{false};
};

/**
 * Outcome of noting a vote. hidden and graduated stay false on every path.
 * A 51 percent vote does not hide a head and does not graduate a candidate.
 */
struct SwarmNotNoVoteHideResult {
    std::string code;
    bool hidden{false};
    bool graduated{false};
};

/**
 * Note that a 51 percent vote does not hide a head and does not graduate a
 * candidate. Order, first match wins: an empty chain_id is CHAIN. majority
 * is VISIBLE, even when want_hide is false. want_hide is HELD. Otherwise
 * the note is NOTED and err is clear. hidden and graduated stay false on
 * every path. A 51 percent vote does not hide a head and does not graduate
 * a candidate.
 */
SwarmNotNoVoteHideResult SwarmNoteNotNoVoteHide(const SwarmNotNoVoteHide& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOVOTEHIDE_H
