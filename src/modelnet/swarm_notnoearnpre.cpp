// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoearnpre.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoEarnPreResult SwarmNoteNotNoEarnPre(const SwarmNotNoEarnPre& note, std::string& err)
{
    SwarmNotNoEarnPreResult result;
    result.recorded = false;
    result.atoms = 0;
    // Earnings are not recorded before settlement. recorded stays false
    // and atoms stays 0 on every path.
    if (note.row_id.empty()) {
        result.code = "ROW";
        result.recorded = false;
        result.atoms = 0;
        err = "ROW";
        return result;
    }
    if (note.unsettled) {
        result.code = "NOT_RECORDED";
        result.recorded = false;
        result.atoms = 0;
        err = "NOT_RECORDED";
        return result;
    }
    if (note.want_record) {
        result.code = "HELD";
        result.recorded = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.recorded = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
