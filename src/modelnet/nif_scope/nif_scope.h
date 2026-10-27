// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_SCOPE_NIF_SCOPE_H
#define BITCOIN_MODELNET_NIF_SCOPE_NIF_SCOPE_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_lanwire/swarm_lanwire.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Privacy scope on every outbound path. A beacon is not permission. WAN stays without a route. */
class NifScope {
public:
    bool SetPolicy(NifPrivacy policy, std::string& err);
    bool ObserveBeacon(const std::string& endpoint, std::string& err);
    bool SendLocal(const std::vector<unsigned char>& payload, std::string& err);
    bool SendWan(std::string& err);
    bool Scan(const std::string& prefix, std::string& err);

    NifPrivacy policy() const { return m_policy; }
    bool granted() const { return false; }
    const std::vector<unsigned char>& received() const { return m_received; }
    int64_t lan_packets() const { return m_lan.packets(); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool connected() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    NifPrivacy m_policy{NifPrivacy::LocalOnly};
    SwarmLanWire m_lan;
    std::vector<unsigned char> m_received;
    std::string m_beacon;
};

} // namespace modelnet

#endif
