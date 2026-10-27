// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DTAT01_DTAT01_H
#define BITCOIN_MODELNET_DTAT01_DTAT01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * DT-AT-01. Closed records for DT-AT-EVD-001 through DT-AT-EVD-008 and
 * DT-AT-NAT-001 through DT-AT-NAT-008.
 *
 * Apply, first match, stores nothing on failure. An empty or unknown id
 * returns ID. Empty text returns FIELD. aux below 0 returns BOUND. aux
 * above 100 returns CAP. flag false returns ABSENT. Exact text vllm,
 * sglang, lmcache, nixl, mooncake, rdma, deepinfer, dualpipe, fp8, or fp4
 * returns NIFDT_ENGINE_ABSENT. Text that contains private returns
 * NIFDT_PRIVATE_DATA. DT-AT-NAT-003 with aux 0 returns EXPIRED. Any other
 * accepted id stores its text once. The same text again returns
 * NIFDT_REPLAY and keeps the first. Different text returns UNCHANGED.
 * DT-AT-EVD-006 stores its text. classification() stays COMPONENT.
 * hardware_qualified() stays false. scenario_status() stays NOT_RUN.
 *
 * Release returns NIFDT_UNQUALIFIED even after every accepted id is stored.
 * release_qualified(), hardware_qualified(), qualified(), advertised(),
 * launched(), gpu(), and broadcast() stay false. gpu_passed() and
 * windows_passed() stay false. hosts() and physical_hosts() stay 1.
 * Hosts with n other than 1 returns HOSTS. Spend returns
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * This class opens no file, socket, or process.
 */
class Dtat01 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool stored(const std::string& id) const;
    std::string text(const std::string& id) const;
    std::string classification() const;
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::string scenario_status() const { return "NOT_RUN"; }

private:
    struct Row {
        std::string id;
        std::string text;
    };
    std::vector<Row> m_rows;
};

} // namespace modelnet

#endif
