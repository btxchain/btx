// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROF01_PROF01_H
#define BITCOIN_MODELNET_PROF01_PROF01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Profile 01. Closed records for the known native, portable, and
 * airgap scenario ids. This class opens no file, socket, or process.
 *
 * Apply: an empty or unknown id returns ID and stores nothing. Empty text
 * returns FIELD. aux below 0 returns BOUND. aux above 100 returns CAP.
 * flag false returns ABSENT. Exact text vllm, sglang, lmcache, nixl,
 * mooncake, rdma, deepinfer, dualpipe, fp8, or fp4 returns
 * NIFDT_ENGINE_ABSENT. private-case-revocation skips the private substring
 * check. Any other text that contains private returns NIFDT_PRIVATE_DATA.
 * Every known id that passes those checks returns NOT_RUN and stores
 * nothing. Apply does not return true.
 *
 * stored() stays false for every id. scenario_status() is NOT_RUN.
 * gpu_passed() and windows_passed() stay false, including for
 * windows-portable, macos-portable, and linux-sm100-deepinfer.
 * Release returns NIFDT_UNQUALIFIED. release_qualified(),
 * hardware_qualified(), qualified(), advertised(), launched(), gpu(),
 * and broadcast() stay false. hosts() and physical_hosts() stay 1.
 * Hosts with n other than 1 returns HOSTS. Spend returns
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0. Vendor and Gpu return
 * NIFDT_ENGINE_ABSENT. classification() is
 * SIMULATION_NOT_HARDWARE_MEASUREMENT.
 */
class Prof01 {
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
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    std::string scenario_status() const { return "NOT_RUN"; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string id;
        std::string text;
    };
    std::vector<Row> m_rows;
};

} // namespace modelnet

#endif
