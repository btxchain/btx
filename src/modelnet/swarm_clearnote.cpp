// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_clearnote.h>

#include <cstdint>

namespace modelnet {

SwarmClearingNoteResult SwarmNoteClearing(const SwarmClearingNote& note, std::string& err)
{
    SwarmClearingNoteResult result;
    result.l1_transactions = 0;
    if (note.payments < 1) {
        result.code = "CLEAR";
        result.l1_transactions = 0;
        err = "CLEAR";
        return result;
    }
    // One clearing note does not emit one L1 transaction per payment
    // and does not broadcast.
    if (note.want_l1_per_payment) {
        result.code = "L1_REFUSED";
        result.l1_transactions = 0;
        err = "L1_REFUSED";
        return result;
    }
    result.code = "NETTED";
    result.l1_transactions = 0;
    err.clear();
    return result;
}

} // namespace modelnet
