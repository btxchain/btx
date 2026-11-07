// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_REL01_REL01_H
#define BITCOIN_MODELNET_REL01_REL01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Rel01. Pass latches. The first Pass calls Liv10::Pass once when that
 * header is present, otherwise Bnd10::Pass once. It then calls Liv24::Pass
 * once when that header is present, otherwise Bnd11::Pass once. A later
 * Pass clears err and returns true without calling those suites again.
 * passed(), release_qualified(), gpu_passed(), and windows_passed() stay
 * false. When the called gate declares one of those methods, a true result
 * fails Pass with NIFDT_UNQUALIFIED and leaves the latch clear. The same
 * failure applies when Rel01 itself reports one of them true.
 * NIF-QA-007, DT-REL-003, DT-REL-007, NT-QA-007, DT-AT-REL-003, and
 * DT-AT-REL-007 stay unqualified. row_qualified() stays false.
 * hosts() and physical_hosts() stay 1. Hosts with n other than 1 returns
 * HOSTS. bytes_moved() stays 0. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), broadcast(), qualified(), hardware_qualified(), and
 * advertised() stay false.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * No archive, tag, or process.
 */
class Rel01 {
public:
    bool Pass(std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool passed() const { return false; }
    bool advertised() const { return false; }
    bool row_qualified(const std::string&) const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
};

} // namespace modelnet

#endif
