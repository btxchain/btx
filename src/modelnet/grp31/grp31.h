// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP31_GRP31_H
#define BITCOIN_MODELNET_GRP31_GRP31_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_kvwire/swarm_kvwire.h>
#include <modelnet/swarm_lanwire/swarm_lanwire.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Group 31 forwards a page to SwarmKvWire and a datagram to SwarmLanWire.
 * This class does not open a socket.
 *
 * Transfer calls SwarmKvWire::Transfer. An empty body is the wire's PAGE
 * error and adds nothing. bytes_moved() is that wire's bytes_moved() plus
 * SwarmLanWire::bytes_moved().
 * Remote calls SwarmKvWire::Remote. nixl, mooncake, and rdma return
 * ENGINE_ABSENT and do not increase bytes.
 * Exchange calls SwarmLanWire::Exchange.
 * Wan calls SwarmLanWire::Wan and returns false with NO_ROUTE.
 * Scan calls SwarmLanWire::Scan and returns false with NOT_SCAN.
 * qualified(), release_qualified(), hardware_qualified(), launched(), gpu(),
 * and broadcast() stay false. hosts() and physical_hosts() stay 1.
 */
class Grp31 {
public:
    bool Transfer(const std::vector<unsigned char>& body, std::string& err);
    bool Remote(const std::string& engine, std::string& err);
    bool Exchange(const std::vector<unsigned char>& payload, std::string& err);
    bool Wan(std::string& err);
    bool Scan(const std::string& prefix, std::string& err);

    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    int64_t bytes_moved() const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    SwarmKvWire m_kv;
    SwarmLanWire m_lan;
};

} // namespace modelnet

#endif
