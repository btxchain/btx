// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP06_GRP06_H
#define BITCOIN_MODELNET_GRP06_GRP06_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Group 6 of the unfinished NIF/DT rows.
 * Requirements: DT-GRD-001, DT-GRD-002, DT-GRD-004, DT-GRD-005, DT-GRD-006, DT-GRD-007, DT-GRD-008, DT-PAR-001, DT-PAR-002, DT-PAR-003, DT-PAR-004, DT-PAR-005, DT-PAR-006, DT-PAR-007, DT-PAR-008
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * automatic_spend() stays "0". No socket, no process, and no broadcast.
 */
class Grp06 {
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
    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif
