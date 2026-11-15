// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocurrencybtx2.h>

#include <string>

namespace modelnet {

SwarmNotNoCurrencyBtx2Result SwarmNoteNotNoCurrencyBtx2(const SwarmNotNoCurrencyBtx2& note, std::string& err)
{
    SwarmNotNoCurrencyBtx2Result result;
    result.renamed = false;
    // The currency stays BTX.
    if (note.quote_id.empty()) {
        result.code = "QUOTE";
        result.renamed = false;
        err = "QUOTE";
        return result;
    }
    if (note.want_rename) {
        result.code = "HELD";
        result.renamed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.renamed = false;
    err.clear();
    return result;
}

} // namespace modelnet
