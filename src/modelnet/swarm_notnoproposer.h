// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROPOSER_H
#define BTX_MODELNET_SWARM_NOTNOPROPOSER_H

#include <string>

namespace modelnet {

/**
 * A local note about one proposal. same_proposer marks the note as coming
 * from the proposal's own proposer. want_sign asks this note to sign that
 * proposal.
 *
 * A proposer does not sign their own proposal. signed_proposal and accepted
 * stay false on every path.
 */
struct SwarmNotNoProposer {
    std::string proposal_id;
    bool same_proposer{false};
    bool want_sign{false};
};

/**
 * Outcome of noting a proposal. signed_proposal and accepted stay false on
 * every path: a proposer does not sign their own proposal.
 */
struct SwarmNotNoProposerResult {
    std::string code;
    bool signed_proposal{false};
    bool accepted{false};
};

/**
 * Note a proposal without signing it.
 * Order, first match wins: an empty proposal_id is PROPOSAL. same_proposer
 * is SAME_SIGNER even when want_sign is false. want_sign is NOT_ACCEPTED.
 * Otherwise the note is NOTED and err is clear.
 * signed_proposal and accepted stay false on every path. A proposer does
 * not sign their own proposal.
 */
SwarmNotNoProposerResult SwarmNoteNotNoProposer(const SwarmNotNoProposer& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROPOSER_H
