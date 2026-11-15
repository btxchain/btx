// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf09/prf09.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Prf09::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (hosts() != static_cast<int64_t>(1) || bytes_moved() != static_cast<int64_t>(0)) {
        err = "HOSTS";
        return false;
    }
    if (multirank(err) || err != "HOSTS") {
        return false;
    }
    if (bytes_moved() != static_cast<int64_t>(0)) {
        err = "HOSTS";
        return false;
    }
    if (Vendor(err) || err != NIFDT_ENGINE_ABSENT) {
        return false;
    }
    if (Gpu(err) || err != NIFDT_ENGINE_ABSENT) {
        return false;
    }
    if (passed() || release_qualified() || gpu_passed() || windows_passed() || hardware_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Prf09::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf09::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf09::multirank(std::string& err)
{
    err = "HOSTS";
    return false;
}

bool Prf09::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf09::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
