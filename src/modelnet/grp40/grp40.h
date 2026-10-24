// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP40_GRP40_H
#define BITCOIN_MODELNET_GRP40_GRP40_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Unknown or empty id. Nothing is stored. */
inline constexpr char GRP40_ID[] = "ID";

/** Empty text. Nothing is stored. */
inline constexpr char GRP40_FIELD[] = "FIELD";

/** aux is below 0. Nothing is stored. */
inline constexpr char GRP40_BOUND[] = "BOUND";

/** aux is above 100. Nothing is stored. */
inline constexpr char GRP40_CAP[] = "CAP";

/** flag is false. Nothing is stored. */
inline constexpr char GRP40_ABSENT[] = "ABSENT";

/** A second text for a stored id. The first text stays. */
inline constexpr char GRP40_UNCHANGED[] = "UNCHANGED";

/** Host count other than 1. hosts() stays 1. */
inline constexpr char GRP40_HOSTS[] = "HOSTS";

/**
 * Group 40. In-memory notes for DS-STD-006, DS-MODEL-001 through
 * DS-MODEL-006, DS-LEARN-001 through DS-LEARN-006, DS-POOL-001 through
 * DS-POOL-006, and DS-PAY-001.
 *
 * Apply checks id, text, aux, flag, remote names, and a private body,
 * in that order. An unknown or empty id is ID. Empty text is FIELD.
 * aux below 0 is BOUND. aux above 100 is CAP. A false flag is ABSENT.
 * Text equal to a name for which NifDtEngineLinked is false is
 * NIFDT_ENGINE_ABSENT. Text containing "private" is NIFDT_PRIVATE_DATA.
 * Each of those refusals stores nothing.
 *
 * DS-PAY-001 and DS-LEARN-006 return NIFDT_UNQUALIFIED and store nothing.
 * Any other known id stores its text once. The same text again is
 * NIFDT_REPLAY and keeps the first text. A different text is UNCHANGED
 * and keeps the first text.
 *
 * Release returns NIFDT_UNQUALIFIED. qualified() and release_qualified()
 * stay false. hosts() and physical_hosts() stay 1. Hosts(2) is HOSTS.
 * Spend returns NIFDT_AUTOMATIC_SPEND. atoms_moved() and bytes_moved()
 * stay 0. Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * This class opens no file, socket, or process.
 */
class Grp40 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool stored(const std::string& id) const;
    std::string text(const std::string& id) const;
    int64_t count() const;

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
    std::map<std::string, std::string> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_GRP40_GRP40_H
