// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bnd08/bnd08.h>
#include <modelnet/liv08/liv08.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Bnd08::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    modelnet::Liv08 liv;
    if (!liv.Pass(err)) {
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Bnd08::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Bnd08::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Bnd08::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Bnd08::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Bnd08::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
