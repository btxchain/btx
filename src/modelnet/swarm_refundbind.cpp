// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_refundbind.h>

namespace modelnet {

// A refund bind record does not bind a leaf and does not broadcast.
SwarmRefundBindResult SwarmBindRefundLocal(const SwarmRefundBind& bind, std::string& err)
{
    SwarmRefundBindResult result;
    result.bound = false;
    result.broadcast = false;
    result.atoms = 0;

    if (bind.channel_id.empty()) {
        result.code = "CHANNEL";
        err = "CHANNEL";
        result.bound = false;
        result.broadcast = false;
        result.atoms = 0;
        return result;
    }
    if (!bind.signer) {
        result.code = "SIGNER";
        err = "SIGNER";
        result.bound = false;
        result.broadcast = false;
        result.atoms = 0;
        return result;
    }
    if (bind.want_broadcast) {
        result.code = "HELD";
        err = "HELD";
        result.bound = false;
        result.broadcast = false;
        result.atoms = 0;
        return result;
    }
    if (bind.want_bind) {
        result.code = "HELD";
        err = "HELD";
        result.bound = false;
        result.broadcast = false;
        result.atoms = 0;
        return result;
    }

    result.code = "NOTED";
    err.clear();
    result.bound = false;
    result.broadcast = false;
    result.atoms = 0;
    return result;
}

} // namespace modelnet
