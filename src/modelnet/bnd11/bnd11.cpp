// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bnd11/bnd11.h>
#include <modelnet/liv24/liv24.h>
#include <modelnet/liv25/liv25.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Bnd11::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    modelnet::Liv24 liv24;
    if (!liv24.Pass(err)) {
        return false;
    }
    modelnet::Liv25 liv25;
    if (!liv25.Pass(err)) {
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Bnd11::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Bnd11::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Bnd11::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Bnd11::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Bnd11::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
