// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notppmfee.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotPpmFeeResult SwarmNoteNotPpmFee(const SwarmNotPpmFee& note, std::string& err)
{
    SwarmNotPpmFeeResult result;
    result.charged = false;
    result.fee_atoms = 0;
    // The forwarder formula base + (amount * ppm + 999999) / 1000000
    // is not charged by this note. fee_atoms stays 0.
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
