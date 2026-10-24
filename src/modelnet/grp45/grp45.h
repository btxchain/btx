// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP45_GRP45_H
#define BITCOIN_MODELNET_GRP45_GRP45_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Group 45. In-memory record for a fixed set of NIF rows.
 * Requirements: NIF-ISL-003, NIF-ISL-004, NIF-ISL-005, NIF-PKG-001,
 * NIF-PKG-002, NIF-PKG-003, NIF-PKG-004, NIF-PKG-005, NIF-DATA-001,
 * NIF-DATA-002, NIF-DATA-003, NIF-DATA-005, NIF-ECON-001, NIF-ECON-002,
 * NIF-ECON-003, NIF-ECON-004, NIF-QA-001, NIF-QA-002, NIF-QA-003.
 *
 * Apply checks, in order:
 * an empty id or an id outside that set is ID and stores nothing;
 * empty text is FIELD and stores nothing;
 * aux below 0 is BOUND and stores nothing;
 * aux above 100 is CAP and stores nothing;
 * flag false is ABSENT and stores nothing;
 * text equal to an engine name for which NifDtEngineLinked is false is
 * NIFDT_ENGINE_ABSENT and stores nothing;
 * text containing "private" is NIFDT_PRIVATE_DATA and stores nothing;
 * NIF-ECON-004 returns NIFDT_AUTOMATIC_SPEND and stores nothing;
 * NIF-PKG-001 returns NIFDT_UNQUALIFIED and stores nothing.
 * Any other accepted id stores one record and Apply returns true.
 * The same text again is NIFDT_REPLAY and keeps the first text and aux.
 * A different text is UNCHANGED and keeps the first text and aux.
 *
 * Release returns NIFDT_UNQUALIFIED. hosts() and physical_hosts() stay 1.
 * Hosts accepts only n equal to 1. Any other n returns HOSTS.
 * Spend returns NIFDT_AUTOMATIC_SPEND. atoms_moved() and bytes_moved()
 * stay 0. qualified() and release_qualified() stay false.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * This class opens no file, no socket, and no process, and it holds no
 * wallet key.
 */
class Grp45 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool stored(const std::string& id) const;
    std::string text_of(const std::string& id) const;
    int64_t aux_of(const std::string& id) const;
    int64_t count() const { return static_cast<int64_t>(m_rows.size()); }

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
    int64_t atoms_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string id;
        std::string text;
        int64_t aux{0};
    };

    const Row* Find(const std::string& id) const;

    std::vector<Row> m_rows;
};

} // namespace modelnet

#endif
