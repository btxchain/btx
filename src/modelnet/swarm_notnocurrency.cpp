// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocurrency.h>

#include <string>

namespace modelnet {

SwarmNotNoCurrencyResult SwarmNoteNotNoCurrency(const SwarmNotNoCurrency& note, std::string& err)
{
    SwarmNotNoCurrencyResult result;
    result.renamed = false;
    result.booked = false;
    // The currency stays BTX.
    if (note.code_id.empty()) {
        result.code = "CODE";
        result.renamed = false;
        result.booked = false;
        err = "CODE";
        return result;
    }
    if (note.code_id != "BTX") {
        result.code = "FIXED";
        result.renamed = false;
        result.booked = false;
        err = "FIXED";
        return result;
    }
    if (note.want_rename) {
        result.code = "FIXED";
        result.renamed = false;
        result.booked = false;
        err = "FIXED";
        return result;
    }
    result.code = "NOTED";
    result.renamed = false;
    result.booked = false;
    err.clear();
    return result;
}

} // namespace modelnet
