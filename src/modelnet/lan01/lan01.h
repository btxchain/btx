// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAN01_LAN01_H
#define BITCOIN_MODELNET_LAN01_LAN01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Lan01 records P2P-SCN-B, P2P-SCN-C, and P2P-SCN-E.
 * Observe applies the first matching rule and opens no socket.
 * scenario is "B", "C", or "E". Anything else is ID.
 * B with manual_address is MANUAL and leaves peers_discovered at 0.
 * B with fewer than two peers is NIFDT_UNQUALIFIED.
 * B with no manual address and at least two peers sets discovered.
 * C with internet_up is ONLINE. C with fewer than two peers is
 * NIFDT_UNQUALIFIED. C with internet_up false and at least two peers
 * returns true.
 * E with bootstrap_lost false is BOOTSTRAP. E with no peer is
 * NIFDT_UNQUALIFIED. E with bootstrap_lost and at least one peer
 * returns true.
 * physical_hosts() stays static_cast<int64_t>(1).
 * passed(), qualified(), release_qualified(), hardware_qualified(),
 * gpu_passed(), windows_passed(), and advertised() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 */
class Lan01 {
public:
    bool Observe(const std::string& scenario, bool manual_address, bool internet_up, bool bootstrap_lost, int peers, std::string& err);

    bool discovered() const { return m_discovered; }
    int peers_discovered() const { return m_peers_discovered; }

    bool passed() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool advertised() const { return false; }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_discovered{false};
    int m_peers_discovered{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAN01_LAN01_H
