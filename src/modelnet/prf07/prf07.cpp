// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf07/prf07.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Prf07::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Prf07::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf07::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
