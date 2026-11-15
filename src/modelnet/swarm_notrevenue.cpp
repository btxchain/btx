// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrevenue.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotRevenueResult SwarmNoteNotRevenue(const SwarmNotRevenue& note, std::string& err)
{
    SwarmNotRevenueResult result;
    result.paid = false;
    result.atoms = 0;
    // A revenue illustration does not pay.
    if (note.split_id.empty()) {
        result.code = "SPLIT";
        result.paid = false;
        result.atoms = 0;
        err = "SPLIT";
        return result;
    }
    if (note.want_pay) {
        result.code = "NOT_PAID";
        result.paid = false;
        result.atoms = 0;
        err = "NOT_PAID";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
