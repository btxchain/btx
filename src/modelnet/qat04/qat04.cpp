// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qat04/qat04.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Qat04::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Qat04::Resume(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Qat04::Serve(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Qat04::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Qat04::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
