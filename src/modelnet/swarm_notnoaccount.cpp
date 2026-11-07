// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoaccount.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmNotNoAccountResult SwarmNoteNotNoAccount(const SwarmNotNoAccount& note, std::string& err)
{
    SwarmNotNoAccountResult result;
    result.paid = false;
    result.atoms = 0;
    // Paynet stays accounting only. A real-money channel pays nothing.
    if (note.ledger_id.empty()) {
        result.code = "LEDGER";
        result.paid = false;
        result.atoms = 0;
        err = "LEDGER";
        return result;
    }
    if (note.real_money) {
        result.code = "REAL_MONEY";
        result.paid = false;
        result.atoms = 0;
        err = "REAL_MONEY";
        return result;
    }
    if (note.want_pay) {
        result.code = "ACCOUNTING_ONLY";
        result.paid = false;
        result.atoms = 0;
        err = "ACCOUNTING_ONLY";
        return result;
    }
    result.code = "NOTED";
    result.paid = false;
    result.atoms = 0;
    err.clear();
    return result;
}

} // namespace modelnet
