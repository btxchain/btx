// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosighashout2.h>

#include <string>

namespace modelnet {

SwarmNotNoSighashOut2Result SwarmNoteNotNoSighashOut2(const SwarmNotNoSighashOut2& note, std::string& err)
{
    SwarmNotNoSighashOut2Result result;
    result.signed_ok = false;
    // A sighash that skips outputs signs nothing.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.signed_ok = false;
        err = "TX";
        return result;
    }
    if (note.skip_outputs) {
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
