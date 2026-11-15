// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_autospent.h>

namespace modelnet {

// Automatic spend stays zero.
SwarmAutoSpentResult SwarmKeepAutoSpend(const SwarmAutoSpent& spend, std::string& err)
{
    SwarmAutoSpentResult out;
    out.armed = false;
    out.atoms = 0;
    if (spend.spend_id.empty()) {
        out.code = "SPEND";
        err = "SPEND";
        out.armed = false;
        out.atoms = 0;
        return out;
    }
    if (spend.want_set) {
        out.code = "HELD";
        err = "HELD";
        out.armed = false;
        out.atoms = 0;
        return out;
    }
    out.code = "NOTED";
    err.clear();
    out.armed = false;
    out.atoms = 0;
    return out;
}

} // namespace modelnet
