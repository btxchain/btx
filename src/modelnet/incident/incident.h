// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_INCIDENT_INCIDENT_H
#define BITCOIN_MODELNET_INCIDENT_INCIDENT_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Empty id or empty text. Nothing is stored. */
inline constexpr char INCIDENT_FIELD[] = "FIELD";

/** Text is exactly blocklist. Nothing is stored. */
inline constexpr char INCIDENT_SCOPE[] = "SCOPE";

/** Host count other than 1. The count stays 1. */
inline constexpr char INCIDENT_HOSTS[] = "HOSTS";

/** A different text. The first text stays. */
inline constexpr char INCIDENT_UNCHANGED[] = "UNCHANGED";

/**
 * One incident record. File stores the first id and text.
 * An empty id or an empty text is FIELD. Text exactly blocklist is SCOPE.
 * Text containing private is NIFDT_PRIVATE_DATA. Text exactly vllm, sglang,
 * lmcache, nixl, mooncake, rdma, deepinfer, dualpipe, fp8, or fp4 is
 * NIFDT_ENGINE_ABSENT. Those refusals store nothing.
 * The same text again is NIFDT_REPLAY. A different text is UNCHANGED.
 * effect_sent(), launched(), gpu(), broadcast(), qualified(),
 * release_qualified(), hardware_qualified(), and passed() stay false.
 * hosts() and physical_hosts() stay 1. Hosts with n other than 1 returns
 * HOSTS. bytes_moved() stays 0. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * This class opens no file, socket, or process.
 */
class Incident {
public:
    bool File(const std::string& id, const std::string& text, std::string& err);
    bool stored(const std::string& id) const;
    std::string text(const std::string& id) const;
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool effect_sent() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool passed() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_set{false};
    std::string m_id;
    std::string m_text;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_INCIDENT_INCIDENT_H
