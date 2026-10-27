// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc03/proc03.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Proc03::Recover(int64_t balance_atoms, bool runtime_up, std::string& err)
{
    if (balance_atoms < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (balance_atoms == static_cast<int64_t>(0)) {
        err = "EMPTY";
        return false;
    }
    if (runtime_up) {
        err = "RUNTIME";
        return false;
    }
    if (m_done) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_recovered = balance_atoms;
    m_runtime_was_down = true;
    m_done = true;
    err.clear();
    return true;
}

} // namespace modelnet
