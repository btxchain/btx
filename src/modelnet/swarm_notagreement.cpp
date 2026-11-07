// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notagreement.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotAgreementResult SwarmNoteNotAgreement(const SwarmNotAgreement& note, std::string& err)
{
    SwarmNotAgreementResult result;
    result.settled = false;
    result.atoms = 0;
    // Agreement is not settlement.
    if (note.agreement_id.empty()) {
        result.code = "AGREEMENT";
        result.settled = false;
        result.atoms = 0;
        err = "AGREEMENT";
        return result;
    }
    if (note.want_settle) {
        result.code = "NOT_SETTLEMENT";
        result.settled = false;
        result.atoms = 0;
        err = "NOT_SETTLEMENT";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
