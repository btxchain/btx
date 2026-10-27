// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/rel01/rel01.h>
#include <modelnet/nifdt_contract/contract.h>

#if __has_include(<modelnet/liv10/liv10.h>)
#include <modelnet/liv10/liv10.h>
#define REL01_LIV10 1
#elif __has_include(<modelnet/bnd10/bnd10.h>)
#include <modelnet/bnd10/bnd10.h>
#define REL01_BND10 1
#endif

#if __has_include(<modelnet/liv24/liv24.h>)
#include <modelnet/liv24/liv24.h>
#define REL01_LIV24 1
#elif __has_include(<modelnet/bnd11/bnd11.h>)
#include <modelnet/bnd11/bnd11.h>
#define REL01_BND11 1
#endif

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kReleaseRows[] = {
    "NIF-QA-007",
    "DT-REL-003",
    "DT-REL-007",
    "NT-QA-007",
    "DT-AT-REL-003",
    "DT-AT-REL-007",
};

} // namespace

bool Rel01::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }

#if defined(REL01_LIV10)
    {
        modelnet::Liv10 liv;
        if (!liv.Pass(err)) {
            return false;
        }
        if (liv.release_qualified()) {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
    }
#elif defined(REL01_BND10)
    {
        modelnet::Bnd10 liv;
        if (!liv.Pass(err)) {
            return false;
        }
        if (liv.passed() || liv.release_qualified() || liv.gpu_passed() || liv.windows_passed()) {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
    }
#endif

#if defined(REL01_LIV24)
    {
        modelnet::Liv24 liv;
        if (!liv.Pass(err)) {
            return false;
        }
        if (liv.release_qualified()) {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
    }
#elif defined(REL01_BND11)
    {
        modelnet::Bnd11 liv;
        if (!liv.Pass(err)) {
            return false;
        }
        if (liv.passed() || liv.release_qualified() || liv.gpu_passed() || liv.windows_passed()) {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
    }
#endif

    if (passed() || release_qualified() || gpu_passed() || windows_passed()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    for (const char* id : kReleaseRows) {
        if (row_qualified(id)) {
            err = NIFDT_UNQUALIFIED;
            return false;
        }
    }

    m_done = true;
    err.clear();
    return true;
}

bool Rel01::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Rel01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Rel01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Rel01::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Rel01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
