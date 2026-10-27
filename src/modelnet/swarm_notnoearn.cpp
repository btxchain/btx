// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoearn.h>

#include <string>

namespace modelnet {

SwarmNotNoEarnResult SwarmNoteNotNoEarn(const SwarmNotNoEarn& note, std::string& err)
{
    SwarmNotNoEarnResult result;
    result.earned = false;
    result.atoms = 0;
    // Earnings are not recorded before settlement and nothing is paid.
    if (note.receipt_id.empty()) {
        result.code = "RECEIPT";
        result.earned = false;
        result.atoms = 0;
        err = "RECEIPT";
        return result;
    }
    if (!note.settled) {
        result.code = "BEFORE_SETTLEMENT";
        result.earned = false;
        result.atoms = 0;
        err = "BEFORE_SETTLEMENT";
        return result;
    }
    if (note.want_earn) {
        result.code = "HELD";
        result.earned = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.earned = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
