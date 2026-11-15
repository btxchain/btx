// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorevenueill2.h>

namespace modelnet {

SwarmNotNoRevenueIll2Result SwarmNoteNotNoRevenueIll2(const SwarmNotNoRevenueIll2& note, std::string& err)
{
    // A revenue illustration records 7000, 2000, and 1000 and pays nothing.
    SwarmNotNoRevenueIll2Result result;
    result.paid = false;
    result.atoms = 0;
    if (note.run_id.empty()) {
        result.code = "RUN";
        result.paid = false;
        result.atoms = 0;
        err = "RUN";
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
