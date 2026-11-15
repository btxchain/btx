// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfiat.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotFiatResult SwarmNoteNotFiat(const SwarmNotFiat& note, std::string& err)
{
    SwarmNotFiatResult result;
    result.counted = false;
    result.atoms = 0;
    // A fiat quote is not a BTX balance.
    if (note.quote_id.empty()) {
        result.code = "QUOTE";
        result.counted = false;
        result.atoms = 0;
        err = "QUOTE";
        return result;
    }
    if (note.want_count) {
        result.code = "NOT_BALANCE";
        result.counted = false;
        result.atoms = 0;
        err = "NOT_BALANCE";
        return result;
    }
    result.code = "NOTED";
    result.counted = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
