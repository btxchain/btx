// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosighash2.h>

#include <string>

namespace modelnet {

SwarmNotNoSighash2Result SwarmNoteNotNoSighash2(const SwarmNotNoSighash2& note, std::string& err)
{
    SwarmNotNoSighash2Result result;
    result.accepted = false;
    result.spent = false;
    // A sighash that does not cover outputs is refused.
    if (note.tx_id.empty()) {
        result.code = "TX";
        result.accepted = false;
        result.spent = false;
        err = "TX";
        return result;
    }
    if (!note.covers_outputs) {
        result.code = "REFUSED";
        result.accepted = false;
        result.spent = false;
        err = "REFUSED";
        return result;
    }
    if (note.want_accept) {
        result.code = "HELD";
        result.accepted = false;
        result.spent = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.spent = false;
    err.clear();
    return result;
}

} // namespace modelnet
