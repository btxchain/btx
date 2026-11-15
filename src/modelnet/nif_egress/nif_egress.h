// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_EGRESS_NIF_EGRESS_H
#define BITCOIN_MODELNET_NIF_EGRESS_NIF_EGRESS_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_lanwire/swarm_lanwire.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** SetScope refused a scope other than local, lan, or peer. The previous scope stays. */
inline constexpr char NIF_EGRESS_SCOPE[] = "SCOPE";

/** Send refused because airgap is set. Exchange is not called. */
inline constexpr char NIF_EGRESS_POLICY[] = "POLICY";

/**
 * NIF-LAN-004 and NIF-LAN-005. Runtime scope is local, lan, or peer.
 * Airgap is a separate whole-node flag and does not change scope().
 *
 * SetScope accepts only "local", "lan", or "peer". Any other value is
 * SCOPE and leaves the previous scope in place. The default scope is local.
 *
 * SetAirgap stores the airgap flag alone. scope() is unchanged.
 *
 * Send with airgap set is POLICY and calls nothing.
 * Scope local stores a non-empty payload in memory and does not call
 * Exchange. The wire's bytes_moved() stays 0 on that path.
 * Scope lan or peer calls SwarmLanWire::Exchange. An empty payload is
 * the error Exchange returns (PAYLOAD) and this class opens no socket
 * of its own. A successful lan exchange reports bytes_moved() equal to
 * the wire's bytes_moved().
 *
 * SendWan calls SwarmLanWire::Wan and returns false with NIFDT_NO_ROUTE.
 * Calling it again does not broaden scope().
 * Scan calls SwarmLanWire::Scan and returns false with NIFDT_NOT_SCAN.
 *
 * hosts() and physical_hosts() stay 1. launched(), gpu(), broadcast(),
 * and qualified() stay false. automatic_spend() returns
 * NIFDT_AUTOMATIC_SPEND.
 */
class NifEgress {
public:
    bool SetScope(const std::string& scope, std::string& err);
    void SetAirgap(bool on);
    bool Send(const std::vector<unsigned char>& payload, std::string& err);
    bool SendWan(std::string& err);
    bool Scan(const std::string& prefix, std::string& err);

    const std::string& scope() const { return m_scope; }
    bool airgap() const { return m_airgap; }
    const std::vector<unsigned char>& received() const { return m_stored; }
    int64_t bytes_moved() const { return m_wire.bytes_moved(); }

    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    static bool KnownScope(const std::string& scope);

    std::string m_scope{"local"};
    bool m_airgap{false};
    SwarmLanWire m_wire;
    std::vector<unsigned char> m_stored;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_EGRESS_NIF_EGRESS_H
