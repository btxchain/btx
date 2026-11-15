// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP22_GRP22_H
#define BITCOIN_MODELNET_GRP22_GRP22_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 22 of the unfinished NIF/DT rows.
 * Requirements: DS-POOL-005, DS-POOL-006, DS-REC-001, DS-REC-002, DS-REC-003, DS-REC-004, DS-REC-005, DS-REC-006, DS-SHARE-001, DS-SHARE-002, DS-SHARE-003, DS-SHARE-004, DS-SHARE-005, DS-SHARE-006, DS-STD-001
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * automatic_spend() stays "0". No file, no socket, no process, and no broadcast.
 * A repeated successful op and text is REPLAY and keeps the first stored row.
 */
class Grp22 {
public:
    bool Apply(const std::string& id, const std::string& op, const std::string& text,
               const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err);
    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    int64_t stored(const std::string& id) const;
    std::string text_of(const std::string& id) const;
    bool bit_of(const std::string& id) const;
    std::string classification(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return 0; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        bool on{false};
        bool bit{false};
        bool has_sig{false};
        int64_t n{0};
        std::string s;
        std::string sig;
    };
    bool Has(const std::string& id) const;
    bool Seen(const std::string& id, const std::string& op, const std::string& text) const;
    void Put(const std::string& id, int64_t n, const std::string& s);
    void SetBit(const std::string& id, bool bit);
    void Remember(const std::string& id, const std::string& op, const std::string& text);
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif
