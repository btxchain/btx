// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowitness2.h>

#include <string>

namespace modelnet {

SwarmNotNoWitness2Result SwarmNoteNotNoWitness2(const SwarmNotNoWitness2& note, std::string& err)
{
    SwarmNotNoWitness2Result result;
    result.signed_witness = false;
    result.spent = false;
    // The scheduler does not sign a funding witness.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.signed_witness = false;
        result.spent = false;
        err = "TX";
        return result;
    }
    // A scheduler is NOT_SIGNED even when want_sign is false.
    if (note.scheduler) {
        result.code = "NOT_SIGNED";
        result.signed_witness = false;
        result.spent = false;
        err = "NOT_SIGNED";
        return result;
    }
    // This note signs nothing. The scheduler does not sign a funding witness.
    if (note.want_sign) {
        result.code = "HELD";
        result.signed_witness = false;
        result.spent = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.signed_witness = false;
    result.spent = false;
    err.clear();
    return result;
}

} // namespace modelnet
