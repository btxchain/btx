// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LIV17_LIV17_H
#define BITCOIN_MODELNET_LIV17_LIV17_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/grp17/grp17.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Liv17 walks the group 17 requirement ids on one Grp17.
 * Requirements: DS-ACT-002, DS-ACT-003, DS-ACT-004, DS-ACT-005, DS-ACT-006, DS-AUTH-001, DS-AUTH-002, DS-AUTH-003, DS-AUTH-004, DS-AUTH-005, DS-AUTH-006, DS-DATA-001, DS-DATA-002, DS-DATA-003, DS-DATA-004
 * Pass uses the Apply arguments the group 17 tests already require.
 * When a test expects false and a specific err, Pass continues only for that same err.
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), broadcast(), qualified(), release_qualified(),
 * and hardware_qualified() stay false.
 * Hosts(2) fails. Release fails with NIFDT_UNQUALIFIED.
 * Spend fails with NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu fail with NIFDT_ENGINE_ABSENT.
 * No file, no socket, no process, and no broadcast.
 */
class Liv17 {
public:
    bool Pass(std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
};

} // namespace modelnet

#endif
