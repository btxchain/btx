// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sighashout.h>

namespace modelnet {

SwarmSighashOutResult SwarmNoteSighashOutputs(const SwarmSighashOut& tx, std::string& err)
{
    SwarmSighashOutResult result;
    result.signed_ok = false;
    if (tx.tx_id.empty()) {
        result.signed_ok = false;
        result.code = "TX";
        err = "TX";
        return result;
    }
    // A sighash that skips outputs is refused.
    if (!tx.covers_outputs) {
        result.signed_ok = false;
        result.code = "NOT_SIGNED";
        err = "NOT_SIGNED";
        return result;
    }
    if (tx.want_sign) {
        result.signed_ok = false;
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.signed_ok = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
