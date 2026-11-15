// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP14_GRP14_H
#define BITCOIN_MODELNET_GRP14_GRP14_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_lanwire/swarm_lanwire.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 14 of the unfinished ASR rows.
 * Requirements: ASR-NAT-005, ASR-NAT-006, ASR-NET-001, ASR-NET-002, ASR-NET-003, ASR-NET-004, ASR-NET-005, ASR-OBS-001, ASR-PAY-001, ASR-PAY-002, ASR-PAY-003, ASR-PAY-004, ASR-PLN-001, ASR-PLN-002, ASR-PLN-003, ASR-PLN-004
 * classification() is COMPONENT. stored() is 0 when the row is off or n is 0.
 * A row may still be on with n == 0; text_of() reads that row.
 * qualified(), release_qualified(), hardware_qualified(), advertised(),
 * launched(), gpu(), and broadcast() stay false.
 * automatic_spend() stays "0". hosts() and physical_hosts() stay 1.
 * bytes_moved() stays 0 even when the LAN wire has moved a datagram.
 * No process. An unknown id is ID. A replay keeps the first stored success.
 * ASR-NET-001 calls SwarmLanWire::Scan. ASR-NET-002 with text "wan" calls
 * SwarmLanWire::Wan. This class does not publish the wire's byte count.
 */
class Grp14 {
public:
    bool Apply(const std::string& id, const std::string& op, const std::string& text,
               const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err);
    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    int64_t stored(const std::string& id) const;
    std::string text_of(const std::string& id) const;
    bool bit_of(const std::string& id) const;
    std::string classification(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        bool on{false};
        bool bit{false};
        int64_t n{0};
        std::string s;
    };
    bool Has(const std::string& id) const;
    void Put(const std::string& id, int64_t n, const std::string& s);
    void SetBit(const std::string& id, bool bit);
    std::map<std::string, Row> m_rows;
    SwarmLanWire m_wire;
};

} // namespace modelnet

#endif
