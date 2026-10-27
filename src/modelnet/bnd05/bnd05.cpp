// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bnd05/bnd05.h>
#include <modelnet/liv05/liv05.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Bnd05::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    modelnet::Liv05 liv;
    if (!liv.Pass(err)) return false;
    m_done = true;
    err.clear();
    return true;
}

bool Bnd05::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Bnd05::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Bnd05::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Bnd05::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Bnd05::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
