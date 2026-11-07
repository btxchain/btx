// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP15_GRP15_H
#define BITCOIN_MODELNET_GRP15_GRP15_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 15 of the unfinished NIF/DT rows.
 * Requirements: ASR-PLN-005, ASR-PLN-006, ASR-PLN-007, ASR-PRG-001, ASR-PRG-002, ASR-PRG-003, ASR-PRG-004, ASR-PRT-001, ASR-PRT-002, ASR-PUB-001, ASR-PUB-002, ASR-PUB-003, ASR-PUB-004, ASR-REC-001, ASR-REC-002
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * automatic_spend() stays "0". No file, no socket, and no process.
 */
class Grp15 {
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
        bool held{false};
        int64_t n{0};
        int64_t passes{0};
        std::string s;
    };
    bool Held(const std::string& id) const;
    void Put(const std::string& id, int64_t n, const std::string& s);
    void SetBit(const std::string& id, bool bit);
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif
