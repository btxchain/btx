// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/set02/set02.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Set02::Note(bool plan_created, bool wallet_submitted, const std::string& txid, int modes_claimed,
                 int modes_settled, std::string& err)
{
    if (modes_claimed < 1) {
        err = "FIELD";
        return false;
    }
    if (!plan_created) {
        err = "ABSENT";
        return false;
    }
    // A plan that the wallet did not submit is not a settlement.
    if (!wallet_submitted) {
        err = "UNSIGNED";
        return false;
    }
    if (txid.empty()) {
        err = "FIELD";
        return false;
    }
    if (static_cast<int64_t>(modes_settled) < static_cast<int64_t>(0)) {
        err = "MODE";
        return false;
    }
    // ASR-PAY-004 needs every claimed mode. One regtest tx does not settle them all.
    if (modes_settled < modes_claimed || modes_settled != modes_claimed) {
        err = "MODE";
        return false;
    }
    m_txid = txid;
    m_modes_settled = modes_settled;
    m_settled = true;
    err.clear();
    return true;
}

} // namespace modelnet
