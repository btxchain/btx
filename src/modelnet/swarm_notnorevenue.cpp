// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorevenue.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoRevenueResult SwarmNoteNotNoRevenue(const SwarmNotNoRevenue& note, std::string& err)
{
    SwarmNotNoRevenueResult result;
    result.paid = false;
    result.atoms = 0;
    // A revenue illustration pays nothing.
    if (note.split_id.empty()) {
        result.code = "SPLIT";
        result.paid = false;
        result.atoms = 0;
        err = "SPLIT";
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
