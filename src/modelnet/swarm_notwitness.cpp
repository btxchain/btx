// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notwitness.h>

#include <string>

namespace modelnet {

SwarmNotWitnessResult SwarmNoteNotWitness(const SwarmNotWitness& note, std::string& err)
{
    SwarmNotWitnessResult result;
    result.verified = false;
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.verified = false;
        err = "TX";
        return result;
    }
    // A signature-size check is not an interpreter-verified funding witness.
    if (note.want_verify) {
        result.code = "UNVERIFIED";
        result.verified = false;
        err = "UNVERIFIED";
        return result;
    }
    result.code = "NOTED";
    result.verified = false;
    err.clear();
    return result;
}

} // namespace modelnet
