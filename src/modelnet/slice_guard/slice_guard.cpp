// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/slice_guard/slice_guard.h>
#include <modelnet/nifdt_contract/contract.h>

#include <string>

namespace modelnet {

bool SliceGuard::Observe(std::string& err)
{
    err = "PROCESS";
    return false;
}

bool SliceGuard::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool SliceGuard::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool SliceGuard::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool SliceGuard::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
