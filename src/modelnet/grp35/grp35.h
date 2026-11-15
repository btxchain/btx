// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP35_GRP35_H
#define BITCOIN_MODELNET_GRP35_GRP35_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 35. One in-process record per known id.
 * Ids: ASR-EVD-003, ASR-EVD-004, ASR-EVD-005, ASR-CAP-001, ASR-CAP-002,
 * ASR-CAP-003, ASR-CAP-004, ASR-ART-001, ASR-ART-002, ASR-ART-003,
 * ASR-ART-004, ASR-ART-005, ASR-KVC-001, ASR-KVC-002, ASR-KVC-003,
 * ASR-KVC-004, ASR-KVC-005, ASR-KVC-006, ASR-TRN-001, ASR-TRN-002.
 *
 * Apply: an empty or unknown id returns ID and stores nothing. Empty text
 * returns FIELD and stores nothing. aux below 0 returns BOUND and stores
 * nothing. aux above 100 returns CAP and stores nothing. flag false returns
 * ABSENT and stores nothing. Text equal to vllm, sglang, lmcache, nixl,
 * mooncake, rdma, deepinfer, dualpipe, or fp8 returns NIFDT_ENGINE_ABSENT
 * and stores nothing. Text containing private returns NIFDT_PRIVATE_DATA
 * and stores nothing. Otherwise the id is stored once. The same id and text
 * again returns NIFDT_REPLAY and keeps the first text. A different text
 * returns UNCHANGED and keeps the first text.
 *
 * Hosts: n other than 1 returns HOSTS. hosts() and physical_hosts() stay 1.
 * Release returns NIFDT_UNQUALIFIED. Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * Spend returns NIFDT_AUTOMATIC_SPEND. qualified(), release_qualified(),
 * hardware_qualified(), launched(), gpu(), and broadcast() stay false.
 * bytes_moved() stays 0. automatic_spend() is "0".
 * This class opens no file, no socket, and starts no process.
 */
class Grp35 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool stored(const std::string& id) const;
    std::string text(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::map<std::string, std::string> m_rows;
};

} // namespace modelnet

#endif
