// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosighash.h>

#include <string>

namespace modelnet {

SwarmNotNoSighashResult SwarmNoteNotNoSighash(const SwarmNotNoSighash& note, std::string& err)
{
    SwarmNotNoSighashResult result;
    result.accepted = false;
    result.spent = false;
    // A sighash that does not cover outputs is refused, and this note
    // spends nothing.
    if (note.sighash_id.empty()) {
        result.code = "SIGHASH";
        result.accepted = false;
        result.spent = false;
        err = "SIGHASH";
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
        result.code = "REFUSED";
        result.accepted = false;
        result.spent = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.spent = false;
    err.clear();
    return result;
}

} // namespace modelnet
