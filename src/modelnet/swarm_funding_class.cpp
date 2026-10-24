// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_funding_class.h>

namespace modelnet {

bool SwarmClassifyMoney(const std::string& kind, int64_t atoms, SwarmMoneyPosition& out, std::string& err)
{
    out = SwarmMoneyPosition{};
    out.kind = kind;
    out.atoms = atoms;
    if (atoms < 0) {
        err = "AMOUNT";
        return false;
    }
    if (kind == "certificate" || kind == "evaluation_certificate") {
        out.counts_as_balance = false;
        out.code = "NOT_MONEY";
        err.clear();
        return true;
    }
    if (kind == "hour-claim" || kind == "gradient-claim") {
        out.counts_as_balance = false;
        out.code = "NOT_CONTRIBUTION";
        err.clear();
        return true;
    }
    if (kind == "promise") {
        out.counts_as_balance = false;
        out.code = "PROMISE";
        err.clear();
        return true;
    }
    if (kind == "observed_utxo") {
        out.counts_as_balance = true;
        out.confirmed_backing = true;
        out.code = "OBSERVED_UTXO";
        err.clear();
        return true;
    }
    if (kind == "escrow") {
        out.counts_as_balance = true;
        out.confirmed_backing = true;
        out.code = "ESCROW";
        err.clear();
        return true;
    }
    if (kind == "channel_capacity") {
        out.counts_as_balance = true;
        out.immediately_payable = true;
        out.code = "CHANNEL_CAPACITY";
        err.clear();
        return true;
    }
    if (kind == "earned_credit") {
        out.counts_as_balance = true;
        out.earned = true;
        out.code = "EARNED_CREDIT";
        err.clear();
        return true;
    }
    if (kind == "confirmed_settlement") {
        out.counts_as_balance = true;
        out.confirmed_backing = true;
        out.code = "CONFIRMED_SETTLEMENT";
        err.clear();
        return true;
    }
    err = "FUNDING_CLASS";
    return false;
}

bool SwarmAcceptCollateralUse(bool already_escrow, bool as_channel, std::string& err)
{
    if (already_escrow && as_channel) {
        err = "COLLATERAL_REUSE";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
