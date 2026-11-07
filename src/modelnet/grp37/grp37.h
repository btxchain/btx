// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP37_GRP37_H
#define BITCOIN_MODELNET_GRP37_GRP37_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 37. In-process record for the listed rows.
 * Requirements: ASR-SEC-001, ASR-SEC-002, ASR-REC-001, ASR-REC-002, ASR-OBS-001,
 * ASR-MIG-001, ASR-MIG-002, ASR-ACC-001, ASR-ACC-002, ASR-PUB-001, ASR-PUB-002,
 * ASR-PUB-003, ASR-PUB-004, DS-NAT-001, DS-NAT-002, DS-NAT-003, DS-NAT-004,
 * DS-NAT-005, DS-NAT-006, DS-HIRE-001.
 *
 * Apply checks id, then text, then aux, then flag, then a remote engine name,
 * then a private body. An unknown or empty id is ID. Empty text is FIELD.
 * aux below 0 is BOUND. aux above 100 is CAP. flag false is ABSENT.
 * A remote engine name (NifDtEngineLinked false) is NIFDT_ENGINE_ABSENT.
 * Text containing the substring private is NIFDT_PRIVATE_DATA.
 * ASR-ACC-002 with text gpu or windows is NIFDT_UNQUALIFIED.
 * gpu_passed() and windows_passed() stay false.
 * Any other call stores that id once. The same text again is NIFDT_REPLAY and
 * keeps the first text and the first aux. A different text is UNCHANGED and
 * keeps the first text and the first aux.
 * ASR-MIG-001 with aux greater than the stored aux is UPGRADE and keeps the
 * first aux and the first text.
 *
 * hosts() and physical_hosts() stay 1. Hosts(n) for n other than 1 is HOSTS.
 * Release is NIFDT_UNQUALIFIED. Spend is NIFDT_AUTOMATIC_SPEND.
 * qualified() and release_qualified() stay false. bytes_moved() stays 0.
 * Vendor and Gpu are NIFDT_ENGINE_ABSENT.
 * This class opens no file, no socket, and no process.
 */
class Grp37 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool stored(const std::string& id) const;
    int64_t aux_of(const std::string& id) const;
    std::string text_of(const std::string& id) const;

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

private:
    struct Row {
        bool on{false};
        int64_t aux{0};
        std::string text;
    };
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif
