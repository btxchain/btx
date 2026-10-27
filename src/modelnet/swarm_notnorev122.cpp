// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorev122.h>

namespace modelnet {

SwarmNotNoRev122Result SwarmNoteNotNoRev122(const SwarmNotNoRev122& note, std::string& err)
{
    // The revenue illustration records 7000, 2000, and 1000 and pays nothing.
    SwarmNotNoRev122Result result;
    result.paid = false;
    result.atoms = 0;
    if (note.row_id.empty()) {
        result.code = "ROW";
        result.paid = false;
        result.atoms = 0;
        err = "ROW";
        return result;
    }
    if (note.want_pay) {
        result.code = "NOT_PAID";
        result.paid = false;
        result.atoms = 0;
        err = "NOT_PAID";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
