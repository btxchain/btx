// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp32/grp32.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool Grp32::Absent(const std::string& name) const
{
    for (const std::string& row : m_absent) {
        if (row == name) return true;
    }
    return false;
}

bool Grp32::linked(const std::string& name) const
{
    for (const std::string& row : m_noted) {
        if (row == name) return true;
    }
    return false;
}

bool Grp32::Note(const std::string& name, std::string& err)
{
    if (name.empty()) {
        err = "NAME";
        return false;
    }
    if (linked(name) || Absent(name)) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (!NifDtEngineLinked(name)) {
        m_absent.push_back(name);
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (name == "memory" || name == "local") {
        m_noted.push_back(name);
        err.clear();
        return true;
    }
    m_absent.push_back(name);
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp32::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp32::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp32::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp32::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp32::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
