// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp31/grp31.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_kvwire/swarm_kvwire.h>
#include <modelnet/swarm_lanwire/swarm_lanwire.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool Grp31::Transfer(const std::vector<unsigned char>& body, std::string& err)
{
    return m_kv.Transfer(body, err);
}

bool Grp31::Remote(const std::string& engine, std::string& err)
{
    const bool ok = m_kv.Remote(engine, err);
    if (engine == "nixl" || engine == "mooncake" || engine == "rdma") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    return ok;
}

bool Grp31::Exchange(const std::vector<unsigned char>& payload, std::string& err)
{
    return m_lan.Exchange(payload, err);
}

bool Grp31::Wan(std::string& err)
{
    (void)m_lan.Wan(err);
    err = NIFDT_NO_ROUTE;
    return false;
}

bool Grp31::Scan(const std::string& prefix, std::string& err)
{
    (void)m_lan.Scan(prefix, err);
    err = NIFDT_NOT_SCAN;
    return false;
}

bool Grp31::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp31::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp31::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp31::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

int64_t Grp31::bytes_moved() const
{
    return static_cast<int64_t>(m_kv.bytes_moved()) + static_cast<int64_t>(m_lan.bytes_moved());
}

} // namespace modelnet
