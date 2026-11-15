// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprofitshare2.h>

#include <string>

namespace modelnet {

SwarmNotNoProfitShare2Result SwarmNoteNotNoProfitShare2(const SwarmNotNoProfitShare2& note, std::string& err)
{
    SwarmNotNoProfitShare2Result result;
    result.paid = false;
    result.atoms = 0;
    if (note.share_id.empty()) {
        result.code = "SHARE";
        result.paid = false;
        result.atoms = 0;
        err = "SHARE";
        return result;
    }
    // A profit share is refused and this note pays nothing.
    if (note.profit) {
        result.code = "NOT_PAID";
        result.paid = false;
        result.atoms = 0;
        err = "NOT_PAID";
        return result;
    }
    if (note.want_pay) {
        result.code = "HELD";
        result.paid = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
