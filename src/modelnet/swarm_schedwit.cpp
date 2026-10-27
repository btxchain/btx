// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit.h>

#include <string>

namespace modelnet {

SwarmSchedWitResult SwarmNoteSchedWitness(const SwarmSchedWit& witness, std::string& err)
{
    SwarmSchedWitResult result;
    result.signed_ok = false;
    // A scheduler witness is not signed.
    if (witness.witness_id.empty()) {
        result.code = "WITNESS";
        result.signed_ok = false;
        err = "WITNESS";
        return result;
    }
    if (witness.scheduler) {
        result.code = "NOT_SIGNED";
        result.signed_ok = false;
        err = "NOT_SIGNED";
        return result;
    }
    if (witness.want_sign) {
        result.code = "HELD";
        result.signed_ok = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.signed_ok = false;
    err.clear();
    return result;
}

} // namespace modelnet
