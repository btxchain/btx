// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoduprcpt.h>

#include <string>

namespace modelnet {

SwarmNotNoDupRcptResult SwarmNoteNotNoDupRcpt(const SwarmNotNoDupRcpt& note, std::string& err)
{
    SwarmNotNoDupRcptResult result;
    result.booked = false;
    result.atoms = 0;
    if (note.receipt_id.empty()) {
        result.code = "RECEIPT";
        result.booked = false;
        result.atoms = 0;
        err = "RECEIPT";
        return result;
    }
    // A duplicate receipt is not booked twice.
    if (note.duplicate) {
        result.code = "NOT_BOOKED";
        result.booked = false;
        result.atoms = 0;
        err = "NOT_BOOKED";
        return result;
    }
    if (note.want_book) {
        result.code = "HELD";
        result.booked = false;
        result.atoms = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.booked = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
