// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourbal.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmFourBalResult SwarmKeepFourBalances(const SwarmFourBal& ledger, std::string& err)
{
    SwarmFourBalResult result;
    result.merged = false;
    result.escrow = 0;
    result.collateral = 0;
    result.earned = 0;
    result.spendable = 0;
    // Four balances stay separate. This record does not merge or spend them.
    if (ledger.ledger_id.empty()) {
        result.code = "LEDGER";
        result.merged = false;
        result.escrow = 0;
        result.collateral = 0;
        result.earned = 0;
        result.spendable = 0;
        err = "LEDGER";
        return result;
    }
    if (ledger.escrow < 0 || ledger.collateral < 0 || ledger.earned < 0 || ledger.spendable < 0) {
        result.code = "RANGE";
        result.merged = false;
        result.escrow = 0;
        result.collateral = 0;
        result.earned = 0;
        result.spendable = 0;
        err = "RANGE";
        return result;
    }
    if (ledger.want_merge) {
        result.code = "HELD";
        result.merged = false;
        result.escrow = ledger.escrow;
        result.collateral = ledger.collateral;
        result.earned = ledger.earned;
        result.spendable = ledger.spendable;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.merged = false;
    result.escrow = ledger.escrow;
    result.collateral = ledger.collateral;
    result.earned = ledger.earned;
    result.spendable = ledger.spendable;
    err.clear();
    return result;
}

} // namespace modelnet
