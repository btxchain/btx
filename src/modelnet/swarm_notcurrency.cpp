// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcurrency.h>

#include <string>

namespace modelnet {

SwarmNotCurrencyResult SwarmNoteNotCurrency(const SwarmNotCurrency& note, std::string& err)
{
    SwarmNotCurrencyResult result;
    result.renamed = false;
    // The currency stays BTX.
    if (note.unit_id.empty()) {
        result.code = "UNIT";
        result.renamed = false;
        err = "UNIT";
        return result;
    }
    if (note.unit_id != "BTX") {
        result.code = "FIXED";
        result.renamed = false;
        err = "FIXED";
        return result;
    }
    if (note.want_rename) {
        result.code = "FIXED";
        result.renamed = false;
        err = "FIXED";
        return result;
    }
    result.code = "NOTED";
    result.renamed = false;
    err.clear();
    return result;
}

} // namespace modelnet
