// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosched2.h>

#include <string>

namespace modelnet {

SwarmNotNoSched2Result SwarmNoteNotNoSched2(const SwarmNotNoSched2& note, std::string& err)
{
    SwarmNotNoSched2Result result;
    result.signed_witness = false;
    // The scheduler does not sign a funding witness.
    if (note.witness_id.empty()) {
        result.code = "WITNESS";
        result.signed_witness = false;
        err = "WITNESS";
        return result;
    }
    // A scheduler is NOT_SIGNED even when want_sign is false.
    if (note.scheduler) {
        result.code = "NOT_SIGNED";
        result.signed_witness = false;
        err = "NOT_SIGNED";
        return result;
    }
    // This note signs nothing. The scheduler does not sign a funding witness.
    if (note.want_sign) {
        result.code = "HELD";
        result.signed_witness = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.signed_witness = false;
    err.clear();
    return result;
}

} // namespace modelnet
