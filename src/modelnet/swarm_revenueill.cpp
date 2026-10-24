// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revenueill.h>

namespace modelnet {

SwarmRevenueIllResult SwarmNoteRevenue(const SwarmRevenueIll& ledger, std::string& err)
{
    // The illustration records 7000, 2000, and 1000 and pays nothing.
    SwarmRevenueIllResult result;
    result.paid = false;
    result.atoms = 0;
    result.illustrated_a = 7000;
    result.illustrated_b = 2000;
    result.illustrated_c = 1000;
    if (ledger.ledger_id.empty()) {
        result.code = "LEDGER";
        result.paid = false;
        result.atoms = 0;
        result.illustrated_a = 7000;
        result.illustrated_b = 2000;
        result.illustrated_c = 1000;
        err = "LEDGER";
        return result;
    }
    if (ledger.want_pay) {
        result.code = "HELD";
        result.paid = false;
        result.atoms = 0;
        result.illustrated_a = 7000;
        result.illustrated_b = 2000;
        result.illustrated_c = 1000;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    result.illustrated_a = 7000;
    result.illustrated_b = 2000;
    result.illustrated_c = 1000;
    err.clear();
    return result;
}

} // namespace modelnet
