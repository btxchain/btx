// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agreehold.h>

namespace modelnet {

// Agreement is not settlement.
SwarmAgreeHoldResult SwarmHoldAgreement(const SwarmAgreeHold& agreement, std::string& err)
{
    SwarmAgreeHoldResult out;
    out.settled = false;
    out.atoms = 0;
    if (agreement.agreement_id.empty()) {
        out.code = "AGREEMENT";
        err = "AGREEMENT";
        return out;
    }
    if (agreement.agreed) {
        out.code = "NOT_SETTLED";
        err = "NOT_SETTLED";
        return out;
    }
    if (agreement.want_settle) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
