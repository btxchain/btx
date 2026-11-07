// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notforwarder.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotForwarderResult SwarmNoteNotForwarder(const SwarmNotForwarder& note, std::string& err)
{
    SwarmNotForwarderResult result;
    result.charged = false;
    result.fee_atoms = 0;
    // A computed forwarder fee is not charged by this note.
    if (note.invoice_id.empty()) {
        result.code = "INVOICE";
        result.charged = false;
        result.fee_atoms = 0;
        err = "INVOICE";
        return result;
    }
    if (note.want_charge) {
        result.code = "NOT_CHARGED";
        result.charged = false;
        result.fee_atoms = 0;
        err = "NOT_CHARGED";
        return result;
    }
    result.code = "NOTED";
    result.charged = false;
    result.fee_atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
