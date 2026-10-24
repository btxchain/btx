// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoschedwit2.h>

#include <string>

namespace modelnet {

SwarmNotNoSchedWit2Result SwarmNoteNotNoSchedWit2(const SwarmNotNoSchedWit2& note, std::string& err)
{
    SwarmNotNoSchedWit2Result result;
    result.signed_ok = false;
    // The scheduler does not sign a funding witness.
    if (note.witness_id.empty()) {
        result.code = "WITNESS";
        result.signed_ok = false;
        err = "WITNESS";
        return result;
    }
    if (note.scheduler) {
        result.code = "NOT_SIGNED";
        result.signed_ok = false;
        err = "NOT_SIGNED";
        return result;
    }
    if (note.want_sign) {
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
