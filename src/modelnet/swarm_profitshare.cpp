// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_profitshare.h>

namespace modelnet {

// A profit share is refused.
SwarmProfitShareRefusal SwarmRefuseProfitShare(const SwarmProfitShareRequest& share, std::string& err)
{
    SwarmProfitShareRefusal out;
    out.shared = false;
    out.atoms = 0;
    if (share.share_id.empty()) {
        out.code = "SHARE";
        err = "SHARE";
        return out;
    }
    if (share.want_share) {
        out.code = "HELD";
        err = "HELD";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
