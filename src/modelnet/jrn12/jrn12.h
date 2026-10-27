// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_JRN12_JRN12_H
#define BITCOIN_MODELNET_JRN12_JRN12_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/dtat01/dtat01.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Journal of DT-AT-01.
 * Pass default-constructs one Dtat01. For every id named in dtat01.h it
 * calls Apply(id, text, aux, flag, err) with the arguments dtat01_tests
 * already requires. scenario_status stays NOT_RUN. When that test expects
 * false and a specific err, Pass continues only for that same err.
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), broadcast(), qualified(), release_qualified(), and
 * hardware_qualified() stay false.
 * Hosts(2) fails. Release fails with NIFDT_UNQUALIFIED.
 * Spend fails with NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu fail with NIFDT_ENGINE_ABSENT.
 * No file, socket, process, or broadcast.
 */
class Jrn12 {
public:
    bool Pass(std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
};

} // namespace modelnet

#endif
