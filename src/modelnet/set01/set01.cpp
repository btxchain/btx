// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/set01/set01.h>

#include <string>

namespace modelnet {

bool Set01::NoteUnsignedPlan(bool plan_created, bool wallet_submitted, const std::string& txid, std::string& err)
{
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
    m_txid = txid;
    m_settled = true;
    err.clear();
    return true;
}

} // namespace modelnet
