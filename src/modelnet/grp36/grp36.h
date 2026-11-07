// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP36_GRP36_H
#define BITCOIN_MODELNET_GRP36_GRP36_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 36. One in-process record per known id.
 * Ids: ASR-TRN-003, ASR-TRN-004, ASR-TRN-005, ASR-EVO-001, ASR-EVO-002,
 * ASR-EVO-003, ASR-EVO-004, ASR-VAL-001, ASR-VAL-002, ASR-VAL-003,
 * ASR-VAL-004, ASR-VAL-005, ASR-PAY-001, ASR-PAY-002, ASR-PAY-003,
 * ASR-PAY-004, ASR-PRT-001, ASR-PRT-002, ASR-RES-001, ASR-RES-002.
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
 * ASR-PAY-001, ASR-PAY-002, ASR-PAY-003, and ASR-PAY-004 store like any
 * other known id. Settle returns NIFDT_UNQUALIFIED. atoms_moved() stays 0.
 *
 * Hosts: n other than 1 returns HOSTS. hosts() and physical_hosts() stay 1.
 * Release returns NIFDT_UNQUALIFIED. Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * Spend returns NIFDT_AUTOMATIC_SPEND. qualified(), release_qualified(),
 * hardware_qualified(), launched(), gpu(), and broadcast() stay false.
 * bytes_moved() stays 0. automatic_spend() is "0".
 * This class opens no file, no socket, and starts no process.
 */
class Grp36 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Settle(std::string& err);
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
    int64_t atoms_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::map<std::string, std::string> m_rows;
};

} // namespace modelnet

#endif
