// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP41_GRP41_H
#define BITCOIN_MODELNET_GRP41_GRP41_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Empty or unknown id. Nothing is stored. */
inline constexpr char GRP41_ID[] = "ID";

/** Empty text. Nothing is stored. */
inline constexpr char GRP41_FIELD[] = "FIELD";

/** aux is below 0. Nothing is stored. */
inline constexpr char GRP41_BOUND[] = "BOUND";

/** aux is above 100. Nothing is stored. */
inline constexpr char GRP41_CAP[] = "CAP";

/** flag is false. Nothing is stored. */
inline constexpr char GRP41_ABSENT[] = "ABSENT";

/** A DS-OPS text other than benign. Nothing is stored. */
inline constexpr char GRP41_FIXTURE[] = "FIXTURE";

/** A second text for a stored id. The first text stays. */
inline constexpr char GRP41_UNCHANGED[] = "UNCHANGED";

/** Hosts other than 1. hosts() stays 1. */
inline constexpr char GRP41_HOSTS[] = "HOSTS";

/**
 * Group 41. Closed record for the known DS-PAY, DS-OPS, DS-EVAL, and DS-REC
 * ids. This class opens no file, socket, or process.
 *
 * Apply checks, in order: unknown or empty id is ID; empty text is FIELD;
 * aux below 0 is BOUND; aux above 100 is CAP; flag false is ABSENT; a text
 * that is a remote engine name (NifDtEngineLinked is false) is
 * NIFDT_ENGINE_ABSENT; text containing "private" is NIFDT_PRIVATE_DATA.
 * Every DS-PAY id then returns NIFDT_UNQUALIFIED and stores nothing.
 * A DS-OPS id whose text is not "benign" returns FIXTURE and stores nothing.
 * DS-EVAL-006 returns NIFDT_UNQUALIFIED and stores nothing.
 * Any other known id stores once. The same text again is NIFDT_REPLAY and
 * keeps the first text. A different text is UNCHANGED and keeps the first.
 *
 * Release returns NIFDT_UNQUALIFIED. hosts() stays 1. Hosts(2) is HOSTS.
 * Spend returns NIFDT_AUTOMATIC_SPEND. atoms_moved() and bytes_moved() stay 0.
 * qualified() and release_qualified() stay false. Vendor and Gpu return
 * NIFDT_ENGINE_ABSENT. effect_sent() stays false.
 */
class Grp41 {
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
    int64_t count() const;

    bool effect_sent() const { return false; }
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

#endif // BITCOIN_MODELNET_GRP41_GRP41_H
