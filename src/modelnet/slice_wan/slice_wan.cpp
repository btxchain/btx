// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/slice_wan/slice_wan.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/realm_roles/realm_roles.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SliceWan::Pass(std::string& err)
{
    static const char* const kRoles[] = {
        "ingress",
        "attestor",
        "controller",
        "mirror-a",
        "mirror-b",
        "endpoint-a",
        "endpoint-b",
        "endpoint-c",
    };
    for (const char* role : kRoles) {
        if (!m_roles.Seat(role, err)) return false;
    }
    if (!m_roles.Advance(static_cast<int64_t>(0), err)) return false;
    if (!m_roles.Advance(static_cast<int64_t>(1), err)) return false;
    if (m_roles.Hosts(static_cast<int64_t>(2), err)) {
        err = "HOSTS";
        return false;
    }
    if (err != "HOSTS") return false;
    err.clear();
    return true;
}

bool SliceWan::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool SliceWan::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
