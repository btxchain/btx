// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmandate.h>

#include <string>

namespace modelnet {

SwarmNotMandateResult SwarmNoteNotMandate(const SwarmNotMandate& note, std::string& err)
{
    SwarmNotMandateResult result;
    result.spent = false;
    result.broadcast = false;
    // automatic_spend_atoms stays 0 until an operator wallet signs a
    // bounded mandate. This note does not spend or broadcast.
    if (note.mandate_id.empty()) {
        result.code = "MANDATE";
        result.spent = false;
        result.broadcast = false;
        err = "MANDATE";
        return result;
    }
    if (!note.operator_signed) {
        result.code = "UNSIGNED";
        result.spent = false;
        result.broadcast = false;
        err = "UNSIGNED";
        return result;
    }
    if (note.want_spend) {
        result.code = "HELD";
        result.spent = false;
        result.broadcast = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.spent = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
