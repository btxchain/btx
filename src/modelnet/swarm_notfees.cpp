// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfees.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotFeesResult SwarmNoteNotFees(const SwarmNotFees& note, std::string& err)
{
    SwarmNotFeesResult result;
    result.published = false;
    result.settled = false;
    result.broadcast = false;
    result.fee_atoms = 0;
    result.latency_us = 0;
    // Fees are unmeasured. Nothing is published, settled, or broadcast.
    if (note.invoice_id.empty()) {
        result.code = "INVOICE";
        result.published = false;
        result.settled = false;
        result.broadcast = false;
        result.fee_atoms = 0;
        result.latency_us = 0;
        err = "INVOICE";
        return result;
    }
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.settled = false;
        result.broadcast = false;
        result.fee_atoms = 0;
        result.latency_us = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.settled = false;
    result.broadcast = false;
    result.fee_atoms = 0;
    result.latency_us = 0;
    err.clear();
    return result;
}

} // namespace modelnet
