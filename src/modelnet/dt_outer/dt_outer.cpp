// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_outer/dt_outer.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool DtOuter::Commit(const std::string& epoch, const std::string& optimizer_state, int64_t membership, bool journal_ok, std::string& err)
{
    if (epoch.empty()) {
        err = DT_OUTER_EPOCH;
        return false;
    }
    if (optimizer_state.empty()) {
        err = DT_OUTER_OPT;
        return false;
    }
    if (membership < static_cast<int64_t>(0)) {
        err = DT_OUTER_MEMBER;
        return false;
    }
    if (!journal_ok) {
        err = DT_OUTER_JOURNAL;
        return false;
    }
    if (m_have && epoch == m_epoch) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_epoch = epoch;
    m_optimizer = optimizer_state;
    m_membership = membership;
    m_have = true;
    err.clear();
    return true;
}

bool DtOuter::Wan(std::string& err)
{
    err = NIFDT_NO_ROUTE;
    return false;
}

} // namespace modelnet
