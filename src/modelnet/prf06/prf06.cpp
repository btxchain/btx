// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf06/prf06.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Prf06::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    m_recorded = true;
    m_done = true;
    err.clear();
    return true;
}

bool Prf06::Hosts(int64_t n, std::string& err)
{
    if (n == static_cast<int64_t>(1)) {
        err.clear();
        return true;
    }
    err = "HOSTS";
    return false;
}

bool Prf06::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf06::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf06::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf06::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Prf06::Archive(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf06::Tag(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf06::VersionBump(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

} // namespace modelnet
