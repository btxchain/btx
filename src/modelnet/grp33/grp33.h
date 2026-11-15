// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP33_GRP33_H
#define BITCOIN_MODELNET_GRP33_GRP33_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 33. One in-process record per known assurance id.
 * Requirements: ASR-NAT-001, ASR-NAT-002, ASR-NAT-003, ASR-NAT-004, ASR-NAT-005, ASR-NAT-006, ASR-GRF-001, ASR-GRF-002, ASR-GRF-003, ASR-GRF-004, ASR-GRF-005, ASR-PLN-001, ASR-PLN-002, ASR-PLN-003, ASR-PLN-004, ASR-PLN-005, ASR-PLN-006, ASR-PLN-007, ASR-EXE-001, ASR-EXE-002.
 *
 * Apply checks id, then text, then aux, then flag, then an absent engine
 * name, then a private body. An empty or unknown id returns ID. Empty text
 * returns FIELD. aux below 0 returns BOUND. aux above 100 returns CAP.
 * flag false returns ABSENT and stores nothing. Text equal to vllm, sglang,
 * lmcache, nixl, mooncake, rdma, deepinfer, dualpipe, or fp8 returns
 * NIFDT_ENGINE_ABSENT and stores nothing. Text containing private returns
 * NIFDT_PRIVATE_DATA and stores nothing. Otherwise text and aux are stored.
 * The same id and text again returns NIFDT_REPLAY and keeps the first aux
 * and text. A different text for that id returns UNCHANGED and keeps the first.
 *
 * Hosts: n other than 1 returns HOSTS. hosts() and physical_hosts() stay 1.
 * Release returns NIFDT_UNQUALIFIED. Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * Spend returns NIFDT_AUTOMATIC_SPEND. automatic_spend() is "0".
 * bytes_moved() stays 0.
 * qualified(), release_qualified(), hardware_qualified(), launched(), gpu(),
 * broadcast(), and advertised() stay false.
 * classification() of an id that starts with P2P- is
 * SIMULATION_NOT_HARDWARE_MEASUREMENT. Any other known id is COMPONENT.
 * This class opens no file, socket, or process, and it does not broadcast.
 */
class Grp33 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    int64_t stored(const std::string& id) const;
    std::string text_of(const std::string& id) const;
    std::string classification(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        bool on{false};
        int64_t n{0};
        std::string s;
    };
    bool Has(const std::string& id) const;
    void Put(const std::string& id, int64_t n, const std::string& text);
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif
