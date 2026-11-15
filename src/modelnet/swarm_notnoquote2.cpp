// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquote2.h>

#include <string>

namespace modelnet {

SwarmNotNoQuote2Result SwarmNoteNotNoQuote2(const SwarmNotNoQuote2& note, std::string& err)
{
    SwarmNotNoQuote2Result result;
    result.booked = false;
    result.atoms = 0;
    if (note.quote_id.empty()) {
        result.code = "QUOTE";
        result.booked = false;
        result.atoms = 0;
        err = "QUOTE";
        return result;
    }
    // A fiat quote is not a BTX balance.
    if (note.fiat) {
        result.code = "NOT_BALANCE";
        result.booked = false;
        result.atoms = 0;
        err = "NOT_BALANCE";
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
