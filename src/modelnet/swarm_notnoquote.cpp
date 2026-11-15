// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquote.h>

#include <string>

namespace modelnet {

SwarmNotNoQuoteResult SwarmNoteNotNoQuote(const SwarmNotNoQuote& note, std::string& err)
{
    SwarmNotNoQuoteResult result;
    result.published = false;
    result.multiplier = 0;
    // A caller-supplied quality quote is not a measurement.
    if (note.quote_id.empty()) {
        result.code = "QUOTE";
        result.published = false;
        result.multiplier = 0;
        err = "QUOTE";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.multiplier = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.multiplier = 0;
    err.clear();
    return result;
}

} // namespace modelnet
