// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/earned.h>

#include <modelnet/swarm_workpay/codes.h>

#include <limits>

namespace modelnet {
namespace {

bool Fits(int64_t have, int64_t atoms)
{
    if (atoms < 1 || have < 0) {
        return false;
    }
    // have + atoms would exceed int64 max.
    return have <= std::numeric_limits<int64_t>::max() - atoms;
}

} // namespace

bool SwarmWorkEarned::Credit(const std::string& receipt, int64_t atoms, std::string& err)
{
    if (receipt.empty()) {
        err = SWARM_WORK_RECEIPT;
        return false;
    }
    if (atoms < 1) {
        err = SWARM_WORK_ATOMS;
        return false;
    }
    if (m_paid.count(receipt) != 0) {
        err = SWARM_WORK_REPLAY;
        return false;
    }
    if (!Fits(m_earned, atoms)) {
        err = SWARM_WORK_ATOMS;
        return false;
    }
    m_earned += atoms;
    m_paid.insert(receipt);
    err.clear();
    return true;
}

int64_t SwarmWorkEarned::earned() const
{
    return m_earned;
}

bool SwarmWorkEarned::paid(const std::string& receipt) const
{
    return m_paid.count(receipt) != 0;
}

} // namespace modelnet
