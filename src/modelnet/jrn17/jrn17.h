// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_JRN17_JRN17_H
#define BITCOIN_MODELNET_JRN17_JRN17_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/dtat06/dtat06.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Jrn17. Pass default-constructs one Dtat06 and calls Apply for every id
 * named by DT-AT-06, with the arguments dtat06_tests already requires.
 * DT-AT-REL-003 and DT-AT-REL-007 stay unqualified and store nothing.
 * A simulation classification stays a simulation. When that test expects
 * false and a specific err, Pass continues only for that same err.
 *
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. launched(), gpu(),
 * broadcast(), qualified(), release_qualified(), and hardware_qualified()
 * stay false. Hosts(2) fails. Release fails with NIFDT_UNQUALIFIED.
 * Spend fails with NIFDT_AUTOMATIC_SPEND. Vendor and Gpu fail with
 * NIFDT_ENGINE_ABSENT.
 * This class opens no file, socket, or process, and it does not broadcast.
 */
class Jrn17 {
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
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
};

} // namespace modelnet

#endif
