// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosighash3.h>

#include <string>

namespace modelnet {

SwarmNotNoSighash3Result SwarmNoteNotNoSighash3(const SwarmNotNoSighash3& note, std::string& err)
{
    SwarmNotNoSighash3Result result;
    result.signed_tx = false;
    result.spent = false;
    // A sighash that skips outputs is refused.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.signed_tx = false;
        result.spent = false;
        err = "TX";
        return result;
    }
    if (note.skips_outputs) {
        result.code = "REFUSED";
        result.signed_tx = false;
        result.spent = false;
        err = "REFUSED";
        return result;
    }
    if (note.want_sign) {
        result.code = "HELD";
        result.signed_tx = false;
        result.spent = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.signed_tx = false;
    result.spent = false;
    err.clear();
    return result;
}

} // namespace modelnet
