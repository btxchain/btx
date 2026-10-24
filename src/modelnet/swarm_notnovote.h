// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOVOTE_H
#define BTX_MODELNET_SWARM_NOTNOVOTE_H

#include <string>

namespace modelnet {

/**
 * A local note about a proposal vote. vote_ppm is the vote in parts per
 * million. want_graduate asks this note to graduate a model.
 *
 * A 51 percent vote does not graduate a model, so graduated and admitted
 * stay false on every path.
 */
struct SwarmNotNoVote {
    std::string proposal_id;
    int vote_ppm{0};
    bool want_graduate{false};
};

/**
 * Outcome of noting a proposal vote. graduated and admitted stay false on
 * every path.
 */
struct SwarmNotNoVoteResult {
    std::string code;
    bool graduated{false};
    bool admitted{false};
};

/**
 * Note that a 51 percent vote does not graduate a model.
 * Order, first match wins: an empty proposal_id is PROPOSAL. vote_ppm at
 * or above 510000 is NOT_GRADUATED even when want_graduate is false.
 * want_graduate is NOT_GRADUATED. Otherwise the note is NOTED and err is
 * clear. graduated and admitted stay false on every path. A 51 percent
 * vote does not graduate a model.
 */
SwarmNotNoVoteResult SwarmNoteNotNoVote(const SwarmNotNoVote& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOVOTE_H
