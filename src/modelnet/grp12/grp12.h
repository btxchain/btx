// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP12_GRP12_H
#define BITCOIN_MODELNET_GRP12_GRP12_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace modelnet {

/**
 * Group 12 of the unfinished NIF/DT rows.
 * Requirements: ASR-EVO-001, ASR-EVO-002, ASR-EVO-003, ASR-EVO-004, ASR-EXE-001, ASR-EXE-002, ASR-EXE-003, ASR-EXE-004, ASR-EXE-005, ASR-EXE-006, ASR-EXE-007, ASR-GRF-001, ASR-GRF-002, ASR-GRF-003, ASR-GRF-004, ASR-GRF-005
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * automatic_spend() stays "0". No file, no socket, no process, and no broadcast.
 */
class Grp12 {
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
        int64_t n{0};
        std::string s;
    };
    bool Has(const std::string& id) const;
    void Put(const std::string& id, int64_t n, const std::string& s);
    void SetBit(const std::string& id, bool bit);
    bool Seen(const std::string& id, const std::string& op, const std::string& text) const;
    void Mark(const std::string& id, const std::string& op, const std::string& text);
    bool Store(const std::string& id, const std::string& op, const std::string& text, int64_t n,
               const std::string& saved, std::string& err);
    std::map<std::string, Row> m_rows;
    std::set<std::string> m_seen;
};

} // namespace modelnet

#endif
