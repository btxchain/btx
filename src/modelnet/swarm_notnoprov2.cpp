// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoprov2.h>

#include <string>

namespace modelnet {

SwarmNotNoProv2Result SwarmNoteNotNoProv2(const SwarmNotNoProv2& note, std::string& err)
{
    SwarmNotNoProv2Result result;
    result.booked = false;
    result.atoms = 0;
    if (note.receipt_id.empty()) {
        result.code = "RECEIPT";
        result.booked = false;
        result.atoms = 0;
        err = "RECEIPT";
        return result;
    }
    // A provisional receipt is not a final booking.
    if (note.provisional) {
        result.code = "NOT_FINAL";
        result.booked = false;
        result.atoms = 0;
        err = "NOT_FINAL";
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
