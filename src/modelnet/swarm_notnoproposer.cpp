// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoproposer.h>

#include <string>

namespace modelnet {

SwarmNotNoProposerResult SwarmNoteNotNoProposer(const SwarmNotNoProposer& note, std::string& err)
{
    SwarmNotNoProposerResult result;
    result.signed_proposal = false;
    result.accepted = false;
    // A proposer does not sign their own proposal.
    if (note.proposal_id.empty()) {
        result.code = "PROPOSAL";
        result.signed_proposal = false;
        result.accepted = false;
        err = "PROPOSAL";
        return result;
    }
    if (note.same_proposer) {
        result.code = "SAME_SIGNER";
        result.signed_proposal = false;
        result.accepted = false;
        err = "SAME_SIGNER";
        return result;
    }
    if (note.want_sign) {
        result.code = "NOT_ACCEPTED";
        result.signed_proposal = false;
        result.accepted = false;
        err = "NOT_ACCEPTED";
        return result;
    }
    result.code = "NOTED";
    result.signed_proposal = false;
    result.accepted = false;
    err.clear();
    return result;
}

} // namespace modelnet
