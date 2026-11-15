// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP43_GRP43_H
#define BITCOIN_MODELNET_GRP43_GRP43_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 43. Closed records for the known P2P-SCN, NIF-NAT, NIF-FORK, and
 * NIF-PROF ids. P2P ids classify as SIMULATION_NOT_HARDWARE_MEASUREMENT.
 * Other ids classify as COMPONENT.
 *
 * Apply(id, text, aux, flag, err) checks, in order: unknown or empty id
 * is ID; empty text is FIELD; aux below 0 is BOUND; aux above 100 is CAP;
 * flag false is ABSENT; a remote engine name, including deepinfer, is
 * NIFDT_ENGINE_ABSENT and stores nothing; text containing private is
 * NIFDT_PRIVATE_DATA and stores nothing; a P2P id whose aux is not 1 is
 * HOSTS; P2P-SCN-M is NIFDT_UNQUALIFIED and stores nothing; NIF-FORK-004
 * and NIF-FORK-005 are NIFDT_ENGINE_ABSENT and store nothing. Any other
 * known id stores once. The same text again is NIFDT_REPLAY and keeps the
 * first record. Different text is UNCHANGED and keeps the first record.
 *
 * hosts() and physical_hosts() stay 1. Release is NIFDT_UNQUALIFIED.
 * qualified_v41() and release_qualified() stay false. Spend is
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() and atoms_moved() stay 0. Vendor
 * and Gpu are NIFDT_ENGINE_ABSENT. This class opens no file, socket, or
 * process.
 */
class Grp43 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool recorded(const std::string& id) const;
    int64_t stored(const std::string& id) const;
    std::string text_of(const std::string& id) const;
    std::string classification(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool qualified_v41() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t atoms_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        int64_t aux{0};
        std::string text;
    };
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_GRP43_GRP43_H
