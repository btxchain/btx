// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qat03/qat03.h>
#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

bool Qat03::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Qat03::LowPrecision(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Qat03::ConditionalMemory(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Qat03::HeldOutTask(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Qat03::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
