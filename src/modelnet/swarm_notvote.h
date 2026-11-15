// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTVOTE_H
#define BTX_MODELNET_SWARM_NOTVOTE_H

#include <string>

namespace modelnet {

/**
 * A local note about a vote. want_graduate asks this note to graduate a
 * model.
 *
 * A 51 percent vote does not graduate a model and does not admit
 * ExactReplay, so graduated and realm_promoted stay false on every path.
 */
struct SwarmNotVote {
    std::string vote_id;
    bool want_graduate{false};
};

/**
 * Outcome of noting a vote. graduated and realm_promoted stay false on
 * every path.
 */
struct SwarmNotVoteResult {
    std::string code;
    bool graduated{false};
    bool realm_promoted{false};
};

/**
 * Note that a 51 percent vote does not graduate a model and does not admit
 * ExactReplay.
 * Order, first match wins: an empty vote_id is VOTE. want_graduate is
 * NOT_GRADUATED. Otherwise the note is NOTED and err is clear.
 * graduated and realm_promoted stay false on every path. A 51 percent
 * vote does not graduate a model and does not admit ExactReplay.
 */
SwarmNotVoteResult SwarmNoteNotVote(const SwarmNotVote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTVOTE_H
