// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qat05/qat05.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Qat05::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Qat05::Wan(std::string& err)
{
    err = NIFDT_NO_ROUTE;
    return false;
}

bool Qat05::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Qat05::Sandbox(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
