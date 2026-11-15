// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP39_GRP39_H
#define BITCOIN_MODELNET_GRP39_GRP39_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Group 39. Closed record for the plan, action, share, and standard rows.
 *
 * Known ids: DS-PLAN-004, DS-PLAN-005, DS-PLAN-006, DS-ACT-001, DS-ACT-002,
 * DS-ACT-003, DS-ACT-004, DS-ACT-005, DS-ACT-006, DS-SHARE-001, DS-SHARE-002,
 * DS-SHARE-003, DS-SHARE-004, DS-SHARE-005, DS-SHARE-006, DS-STD-001,
 * DS-STD-002, DS-STD-003, DS-STD-004, DS-STD-005.
 *
 * Apply checks, in order: an empty or unknown id returns ID and stores
 * nothing. An empty text returns FIELD. aux below 0 returns BOUND. aux
 * above 100 returns CAP. flag false returns ABSENT. A remote engine name
 * in text, one for which NifDtEngineLinked is false, returns
 * NIFDT_ENGINE_ABSENT. Text containing private returns NIFDT_PRIVATE_DATA.
 * DS-ACT-002 with text D3 returns APPROVAL even when flag is true, and
 * stores nothing. DS-SHARE-002 returns EMBARGO and stores nothing.
 * Any other accepted call stores that id once.
 * The same text again returns NIFDT_REPLAY and keeps the first text.
 * A different text returns UNCHANGED and keeps the first text.
 *
 * Release returns NIFDT_UNQUALIFIED even after every other id is stored.
 * qualified() and release_qualified() stay false.
 * hosts() and physical_hosts() stay 1. Hosts(n) for n other than 1 returns
 * HOSTS. Spend returns NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * This class opens no file, socket, or process.
 */
class Grp39 {
public:
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool stored(const std::string& id) const;
    std::string text_of(const std::string& id) const;
    int64_t aux_of(const std::string& id) const;

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
