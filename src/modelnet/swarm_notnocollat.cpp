// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocollat.h>

#include <string>

namespace modelnet {

SwarmNotNoCollatResult SwarmNoteNotNoCollat(const SwarmNotNoCollat& note, std::string& err)
{
    SwarmNotNoCollatResult result;
    result.booked = false;
    result.atoms = 0;
    if (note.book_id.empty()) {
        result.code = "BOOK";
        result.booked = false;
        result.atoms = 0;
        err = "BOOK";
        return result;
    }
    // Reused collateral is not booked again.
    if (note.reused) {
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
