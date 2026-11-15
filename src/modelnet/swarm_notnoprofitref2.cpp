// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprofitref2.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoProfitRef2Result SwarmNoteNotNoProfitRef2(const SwarmNotNoProfitRef2& note, std::string& err)
{
    SwarmNotNoProfitRef2Result result;
    result.shared = false;
    result.atoms = 0;
    // Profit-share is refused.
    if (note.share_id.empty()) {
        result.code = "SHARE";
        result.shared = false;
        result.atoms = 0;
        err = "SHARE";
        return result;
    }
    if (note.want_share) {
        result.code = "HELD";
        result.shared = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
