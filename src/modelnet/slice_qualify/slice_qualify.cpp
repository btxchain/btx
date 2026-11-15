// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/slice_qualify/slice_qualify.h>
#include <modelnet/nifdt_contract/contract.h>


#include <string>

namespace modelnet {

bool SliceQualify::Observe(const std::string& text, std::string& err)
{
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (text == "windows" || text == "macos" || text == "gpu") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    err = "JOURNEY";
    return false;
}

bool SliceQualify::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool SliceQualify::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool SliceQualify::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool SliceQualify::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
