// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag11.h>

#include <string>

namespace modelnet {

SwarmFlag11Result SwarmStagePay(const SwarmFlag11& in, std::string& err)
{
    SwarmFlag11Result result;
    // Isolated regtest settlement stays unbroadcast. Do not mine and do
    // not store a txid.
    result.settled = false;
    result.broadcast = false;
    result.mined = false;
    result.passed = false;
    result.txid.clear();

    if (in.invoice_id.empty()) {
        result.code = "INVOICE";
        result.settled = false;
        result.broadcast = false;
        result.mined = false;
        result.passed = false;
        result.txid.clear();
        err = "INVOICE";
        return result;
    }
    if (!in.regtest) {
        result.code = "MAINNET";
        result.settled = false;
        result.broadcast = false;
        result.mined = false;
        result.passed = false;
        result.txid.clear();
        err = "MAINNET";
        return result;
    }
    if (in.want_mine) {
        result.code = "NOT_MINED";
        result.settled = false;
        result.broadcast = false;
        result.mined = false;
        result.passed = false;
        result.txid.clear();
        err = "NOT_MINED";
        return result;
    }
    if (in.want_settle) {
        result.code = "NOT_SETTLED";
        result.settled = false;
        result.broadcast = false;
        result.mined = false;
        result.passed = false;
        result.txid.clear();
        err.clear();
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.settled = false;
        result.broadcast = false;
        result.mined = false;
        result.passed = false;
        result.txid.clear();
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.settled = false;
    result.broadcast = false;
    result.mined = false;
    result.passed = false;
    result.txid.clear();
    err.clear();
    return result;
}

} // namespace modelnet
