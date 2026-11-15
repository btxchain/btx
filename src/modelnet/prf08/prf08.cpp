// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf08/prf08.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Prf08::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (hosts() != static_cast<int64_t>(1) || physical_hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (Hosts(static_cast<int64_t>(2), err) || err != "HOSTS") {
        return false;
    }
    if (Wan(static_cast<int64_t>(3), err) || err != NIFDT_NO_ROUTE) {
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

bool Prf08::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Prf08::Wan(int64_t n, std::string& err)
{
    static_cast<void>(n);
    err = NIFDT_NO_ROUTE;
    return false;
}

bool Prf08::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf08::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
