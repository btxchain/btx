// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprofit.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoProfitResult SwarmNoteNotNoProfit(const SwarmNotNoProfit& note, std::string& err)
{
    SwarmNotNoProfitResult result;
    result.paid = false;
    result.atoms = 0;
    // Profit-share is refused and this note pays nothing.
    if (note.split_id.empty()) {
        result.code = "SPLIT";
        result.paid = false;
        result.atoms = 0;
        err = "SPLIT";
        return result;
    }
    if (note.want_share) {
        result.code = "REFUSED";
        result.paid = false;
        result.atoms = 0;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
