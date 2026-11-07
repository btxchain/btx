// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_escrowboth.h>

#include <string>

namespace modelnet {

SwarmEscrowBothResult SwarmNoteEscrowBoth(const SwarmEscrowBoth& ledger, std::string& err)
{
    SwarmEscrowBothResult result;
    result.booked = false;
    result.atoms = 0;
    if (ledger.ledger_id.empty()) {
        result.code = "LEDGER";
        result.booked = false;
        result.atoms = 0;
        err = "LEDGER";
        return result;
    }
    // The same atoms are never both escrow and collateral.
    if (ledger.same_atoms) {
        result.code = "NOT_BOTH";
        result.booked = false;
        result.atoms = 0;
        err = "NOT_BOTH";
        return result;
    }
    if (ledger.want_book) {
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
