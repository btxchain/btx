// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_gradagree/dt_gradagree.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool DtGradAgree::Slot(int64_t rank, int& slot) const
{
    if (rank == static_cast<int64_t>(0)) {
        slot = 0;
        return true;
    }
    if (rank == static_cast<int64_t>(1)) {
        slot = 1;
        return true;
    }
    return false;
}

bool DtGradAgree::Submit(int64_t rank, int64_t value, std::string& err)
{
    int slot = 0;
    if (!Slot(rank, slot)) {
        err = DT_GRADAGREE_RANK;
        return false;
    }
    if (m_has[slot]) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_value[slot] = value;
    m_has[slot] = true;
    err.clear();
    return true;
}

bool DtGradAgree::Agree(std::string& err)
{
    if (m_agreed) {
        err = DT_GRADAGREE_UNCHANGED;
        return false;
    }
    if (submitted() < static_cast<int64_t>(2)) {
        err = DT_GRADAGREE_MISSING;
        return false;
    }
    if (m_value[0] != m_value[1]) {
        err = DT_GRADAGREE_DISAGREE;
        return false;
    }
    m_agreed = true;
    err.clear();
    return true;
}

bool DtGradAgree::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

int64_t DtGradAgree::submitted() const
{
    int64_t count = static_cast<int64_t>(0);
    if (m_has[0]) count += static_cast<int64_t>(1);
    if (m_has[1]) count += static_cast<int64_t>(1);
    return count;
}

int64_t DtGradAgree::gradient(int64_t rank) const
{
    int slot = 0;
    if (!Slot(rank, slot) || !m_has[slot]) return static_cast<int64_t>(0);
    return m_value[slot];
}

} // namespace modelnet
