// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MOD01_MOD01_H
#define BITCOIN_MODELNET_MOD01_MOD01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Mod01. Closed records for git_origin, git_attestation, agent_lineage,
 * agent_guard, incident, realm_promotion, fleet_rollout, git_remote,
 * slice_source, slice_views, slice_replay, slice_admit, slice_guard,
 * slice_wan, and slice_qualify.
 *
 * Apply, first match, stores nothing on failure. An empty or unknown id
 * returns ID. Empty text returns FIELD. aux below 0 returns BOUND. aux
 * above 100 returns CAP. flag false returns ABSENT. Text exactly vllm,
 * sglang, lmcache, nixl, mooncake, rdma, deepinfer, dualpipe, fp8, or fp4
 * returns NIFDT_ENGINE_ABSENT. Text that contains private returns
 * NIFDT_PRIVATE_DATA. slice_qualify with text exactly windows, macos, or
 * gpu returns NIFDT_UNQUALIFIED. slice_source, slice_views, slice_replay,
 * slice_admit, slice_guard, slice_wan, and any other slice_qualify text
 * return JOURNEY. git_origin with text exactly sha1 returns DIGEST.
 * git_attestation with text exactly account returns ATTEST. agent_lineage
 * with text exactly inherit returns GRANT. agent_guard with text exactly
 * inprocess returns PROCESS and process_present() stays false. incident
 * with text exactly blocklist returns SCOPE. realm_promotion with text
 * exactly one returns QUORUM. fleet_rollout with text exactly complete
 * returns STATE. git_remote with text exactly shell returns HELPER. Any
 * other accepted id stores its text once. The same text again returns
 * NIFDT_REPLAY and keeps the first. Different text returns UNCHANGED.
 *
 * passed() stays false after every call. process_present(),
 * release_qualified(), hardware_qualified(), qualified(), advertised(),
 * launched(), gpu(), broadcast(), gpu_passed(), and windows_passed() stay
 * false. hosts() and physical_hosts() stay 1. Hosts with n other than 1
 * returns HOSTS. Release returns NIFDT_UNQUALIFIED. Spend returns
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0. Vendor and Gpu return
 * NIFDT_ENGINE_ABSENT. classification() is
 * SIMULATION_NOT_HARDWARE_MEASUREMENT.
 * This class opens no file, socket, or process.
 */
class Mod01 {
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
    bool passed() const { return false; }
    bool process_present() const { return false; }
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
