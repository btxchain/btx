// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agreement.h>

#include <cstdint>

namespace modelnet {

SwarmAgreementResult SwarmNoteAgreement(const SwarmAgreement& note, std::string& err)
{
    SwarmAgreementResult result;
    result.settled = false;
    result.atoms_moved = 0;
    if (note.candidate_id.empty()) {
        result.code = "AGREE";
        result.settled = false;
        result.atoms_moved = 0;
        err = "AGREE";
        return result;
    }
    // Disagreement is recorded before any settle request.
    if (!note.outcomes_agree) {
        result.code = "SPLIT";
        result.settled = false;
        result.atoms_moved = 0;
        err = "SPLIT";
        return result;
    }
    // Agreement is not settlement. Do not broadcast.
    if (note.want_settle) {
        result.code = "NOT_SETTLEMENT";
        result.settled = false;
        result.atoms_moved = 0;
        err = "NOT_SETTLEMENT";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.atoms_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
