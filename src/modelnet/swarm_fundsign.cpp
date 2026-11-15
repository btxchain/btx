// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fundsign.h>

namespace modelnet {

SwarmFundingWitnessResult SwarmNoteFundingWitness(const SwarmFundingWitness& witness, std::string& err)
{
    SwarmFundingWitnessResult result;
    result.signed_witness = false;
    result.broadcast = false;
    if (witness.scheduler_id.empty()) {
        result.code = "WITNESS";
        err = "WITNESS";
        return result;
    }
    // SIGN_REFUSED wins even when want_broadcast is true.
    // The scheduler does not sign a funding witness.
    if (witness.scheduler_signs) {
        result.signed_witness = false;
        result.broadcast = false;
        result.code = "SIGN_REFUSED";
        err = "SIGN_REFUSED";
        return result;
    }
    if (witness.want_broadcast) {
        result.signed_witness = false;
        result.broadcast = false;
        result.code = "BROADCAST_FORBIDDEN";
        err = "BROADCAST_FORBIDDEN";
        return result;
    }
    // Nothing is signed and nothing is broadcast.
    result.signed_witness = false;
    result.broadcast = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
