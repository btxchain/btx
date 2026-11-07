// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnofiatquote2.h>

#include <string>

namespace modelnet {

SwarmNotNoFiatQuote2Result SwarmNoteNotNoFiatQuote2(const SwarmNotNoFiatQuote2& note, std::string& err)
{
    SwarmNotNoFiatQuote2Result result;
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
